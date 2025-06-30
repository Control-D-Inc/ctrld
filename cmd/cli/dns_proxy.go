package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

const (
	staleTTL = 60 * time.Second
	localTTL = 3600 * time.Second
	// EDNS0_OPTION_MAC is dnsmasq EDNS0 code for adding mac option.
	// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/dns-protocol.h;h=76ac66a8c28317e9c121a74ab5fd0e20f6237dc8;hb=HEAD#l81
	// This is also dns.EDNS0LOCALSTART, but define our own constant here for clarification.
	EDNS0_OPTION_MAC = 0xFDE9

	// selfUninstallMaxQueries is number of REFUSED queries seen before checking for self-uninstallation.
	selfUninstallMaxQueries = 32
)

var osUpstreamConfig = &ctrld.UpstreamConfig{
	Name:    "OS resolver",
	Type:    ctrld.ResolverTypeOS,
	Timeout: 3000,
}

var privateUpstreamConfig = &ctrld.UpstreamConfig{
	Name:    "Private resolver",
	Type:    ctrld.ResolverTypePrivate,
	Timeout: 2000,
}

var localUpstreamConfig = &ctrld.UpstreamConfig{
	Name:    "Local resolver",
	Type:    ctrld.ResolverTypeLocal,
	Timeout: 2000,
}

// proxyRequest contains data for proxying a DNS query to upstream.
type proxyRequest struct {
	msg            *dns.Msg
	ci             *ctrld.ClientInfo
	failoverRcodes []int
	ufr            *upstreamForResult
}

// proxyResponse contains data for proxying a DNS response from upstream.
type proxyResponse struct {
	answer     *dns.Msg
	upstream   string
	cached     bool
	clientInfo bool
	refused    bool
}

// upstreamForResult represents the result of processing rules for a request.
type upstreamForResult struct {
	upstreams      []string
	matchedPolicy  string
	matchedNetwork string
	matchedRule    string
	matched        bool
	srcAddr        string
}

// serveDNS sets up and starts a DNS server on the specified listener, handling DNS queries and network monitoring.
func (p *prog) serveDNS(mainCtx context.Context, listenerNum string) error {
	if err := p.monitorNetworkChanges(mainCtx); err != nil {
		p.Error().Err(err).Msg("Failed to start network monitoring")
		// Don't return here as we still want DNS service to run
	}

	listenerConfig := p.cfg.Listener[listenerNum]
	if allocErr := p.allocateIP(listenerConfig.IP); allocErr != nil {
		p.Error().Err(allocErr).Str("ip", listenerConfig.IP).Msg("serveUDP: failed to allocate listen ip")
		return allocErr
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		p.handleDNSQuery(w, m, listenerNum, listenerConfig)
	})

	return p.startListeners(mainCtx, listenerConfig, handler)
}

// startListeners starts DNS listeners on specified configurations, supporting UDP and TCP protocols.
// It handles local IPv6, RFC 1918, and specified IP listeners, reacting to stop signals or errors.
func (p *prog) startListeners(ctx context.Context, cfg *ctrld.ListenerConfig, handler dns.Handler) error {
	g, gctx := errgroup.WithContext(ctx)

	for _, proto := range []string{"udp", "tcp"} {
		if needLocalIPv6Listener() {
			g.Go(func() error {
				s, errCh := runDNSServer(net.JoinHostPort("::1", strconv.Itoa(cfg.Port)), proto, handler)
				defer s.Shutdown()
				select {
				case <-p.stopCh:
				case <-gctx.Done():
				case err := <-errCh:
					p.Warn().Err(err).Msg("local ipv6 listener failed")
				}
				return nil
			})
		}

		if needRFC1918Listeners(cfg) {
			g.Go(func() error {
				for _, addr := range ctrld.Rfc1918Addresses() {
					func() {
						listenAddr := net.JoinHostPort(addr, strconv.Itoa(cfg.Port))
						s, errCh := runDNSServer(listenAddr, proto, handler)
						defer s.Shutdown()
						select {
						case <-p.stopCh:
						case <-gctx.Done():
						case err := <-errCh:
							p.Warn().Err(err).Msgf("could not listen on %s: %s", proto, listenAddr)
						}
					}()
				}
				return nil
			})
		}

		g.Go(func() error {
			addr := net.JoinHostPort(cfg.IP, strconv.Itoa(cfg.Port))
			s, errCh := runDNSServer(addr, proto, handler)
			defer s.Shutdown()
			p.started <- struct{}{}
			select {
			case <-p.stopCh:
			case <-gctx.Done():
			case err := <-errCh:
				return err
			}
			return nil
		})
	}

	return g.Wait()
}

// handleDNSQuery processes incoming DNS queries, validates client access, and routes the query to appropriate handlers.
func (p *prog) handleDNSQuery(w dns.ResponseWriter, m *dns.Msg, listenerNum string, listenerConfig *ctrld.ListenerConfig) {
	p.sema.acquire()
	defer p.sema.release()

	if len(m.Question) == 0 {
		sendDNSResponse(w, m, dns.RcodeFormatError)
		return
	}

	reqID := requestID()
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, reqID)
	ctx = ctrld.LoggerCtx(ctx, p.logger.Load())

	if !listenerConfig.AllowWanClients && isWanClient(w.RemoteAddr()) {
		ctrld.Log(ctx, p.Debug(), "query refused, listener does not allow WAN clients: %s", w.RemoteAddr().String())
		sendDNSResponse(w, m, dns.RcodeRefused)
		return
	}

	go p.detectLoop(m)

	q := m.Question[0]
	domain := canonicalName(q.Name)

	if p.handleSpecialDomains(ctx, w, m, domain) {
		return
	}
	p.processStandardQuery(&standardQueryRequest{
		ctx:            ctx,
		writer:         w,
		msg:            m,
		listenerNum:    listenerNum,
		listenerConfig: listenerConfig,
		domain:         domain,
	})
}

// handleSpecialDomains processes special domain queries, handles errors, purges cache if necessary, and returns a bool status.
func (p *prog) handleSpecialDomains(ctx context.Context, w dns.ResponseWriter, m *dns.Msg, domain string) bool {
	switch {
	case domain == "":
		sendDNSResponse(w, m, dns.RcodeFormatError)
		return true
	case domain == selfCheckInternalTestDomain:
		answer := resolveInternalDomainTestQuery(ctx, domain, m)
		_ = w.WriteMsg(answer)
		return true
	}

	if _, ok := p.cacheFlushDomainsMap[domain]; ok && p.cache != nil {
		p.cache.Purge()
		ctrld.Log(ctx, p.Debug(), "received query %q, local cache is purged", domain)
	}

	return false
}

// standardQueryRequest represents a standard DNS query request with associated context and configuration.
type standardQueryRequest struct {
	ctx            context.Context
	writer         dns.ResponseWriter
	msg            *dns.Msg
	listenerNum    string
	listenerConfig *ctrld.ListenerConfig
	domain         string
}

// processStandardQuery handles a standard DNS query by routing it through appropriate upstreams and writing a DNS response.
func (p *prog) processStandardQuery(req *standardQueryRequest) {
	remoteIP, _, _ := net.SplitHostPort(req.writer.RemoteAddr().String())
	ci := p.getClientInfo(remoteIP, req.msg)
	ci.ClientIDPref = p.cfg.Service.ClientIDPref

	stripClientSubnet(req.msg)
	remoteAddr := spoofRemoteAddr(req.writer.RemoteAddr(), ci)
	fmtSrcToDest := fmtRemoteToLocal(req.listenerNum, ci.Hostname, remoteAddr.String())

	startTime := time.Now()
	q := req.msg.Question[0]
	ctrld.Log(req.ctx, p.Info(), "QUERY: %s: %s %s", fmtSrcToDest, dns.TypeToString[q.Qtype], req.domain)

	ur := p.upstreamFor(req.ctx, req.listenerNum, req.listenerConfig, remoteAddr, ci.Mac, req.domain)

	var answer *dns.Msg
	// Handle restricted listener case
	if !ur.matched && req.listenerConfig.Restricted {
		ctrld.Log(req.ctx, p.Debug(), "query refused, %s does not match any network policy", remoteAddr.String())
		answer = new(dns.Msg)
		answer.SetRcode(req.msg, dns.RcodeRefused)
		// Process the refused query
		go p.postProcessStandardQuery(ci, req.listenerConfig, q, &proxyResponse{answer: answer, refused: true})
	} else {
		// Process a normal query
		pr := p.proxy(req.ctx, &proxyRequest{
			msg:            req.msg,
			ci:             ci,
			failoverRcodes: p.getFailoverRcodes(req.listenerConfig),
			ufr:            ur,
		})

		rtt := time.Since(startTime)
		ctrld.Log(req.ctx, p.Debug(), "received response of %d bytes in %s", pr.answer.Len(), rtt)

		go p.postProcessStandardQuery(ci, req.listenerConfig, q, pr)
		answer = pr.answer
	}

	if err := req.writer.WriteMsg(answer); err != nil {
		ctrld.Log(req.ctx, p.Error().Err(err), "serveDNS: failed to send DNS response to client")
	}
}

// postProcessStandardQuery performs additional actions after processing a standard DNS query, such as metrics recording,
// handling canonical name adjustments, and triggering specific post-query actions like uninstallation procedures.
func (p *prog) postProcessStandardQuery(ci *ctrld.ClientInfo, listenerConfig *ctrld.ListenerConfig, q dns.Question, pr *proxyResponse) {
	p.doSelfUninstall(pr)
	p.recordMetrics(ci, listenerConfig, q, pr)
	p.forceFetchingAPI(canonicalName(q.Name))
}

// getFailoverRcodes retrieves the failover response codes from the provided ListenerConfig. Returns nil if no policy exists.
func (p *prog) getFailoverRcodes(cfg *ctrld.ListenerConfig) []int {
	if cfg.Policy != nil {
		return cfg.Policy.FailoverRcodeNumbers
	}
	return nil
}

// recordMetrics updates Prometheus metrics for DNS queries, including query count and client-specific query statistics.
func (p *prog) recordMetrics(ci *ctrld.ClientInfo, cfg *ctrld.ListenerConfig, q dns.Question, pr *proxyResponse) {
	upstream := pr.upstream
	switch {
	case pr.cached:
		upstream = "cache"
	case pr.clientInfo:
		upstream = "client_info_table"
	}
	labelValues := []string{
		net.JoinHostPort(cfg.IP, strconv.Itoa(cfg.Port)),
		ci.IP,
		ci.Mac,
		ci.Hostname,
		upstream,
		dns.TypeToString[q.Qtype],
		dns.RcodeToString[pr.answer.Rcode],
	}
	p.WithLabelValuesInc(statsQueriesCount, labelValues...)
	p.WithLabelValuesInc(statsClientQueriesCount, []string{ci.IP, ci.Mac, ci.Hostname}...)
}

// sendDNSResponse sends a DNS response with the specified RCODE to the client using the provided ResponseWriter.
func sendDNSResponse(w dns.ResponseWriter, m *dns.Msg, rcode int) {
	answer := new(dns.Msg)
	answer.SetRcode(m, rcode)
	_ = w.WriteMsg(answer)
}

// upstreamFor returns the list of upstreams for resolving the given domain,
// matching by policies defined in the listener config. The second return value
// reports whether the domain matches the policy.
//
// Though domain policy has higher priority than network policy, it is still
// processed later, because policy logging want to know whether a network rule
// is disregarded in favor of the domain level rule.
func (p *prog) upstreamFor(ctx context.Context, defaultUpstreamNum string, lc *ctrld.ListenerConfig, addr net.Addr, srcMac, domain string) (res *upstreamForResult) {
	upstreams := []string{upstreamPrefix + defaultUpstreamNum}
	matchedPolicy := "no policy"
	matchedNetwork := "no network"
	matchedRule := "no rule"
	matched := false
	res = &upstreamForResult{srcAddr: addr.String()}

	defer func() {
		res.upstreams = upstreams
		res.matched = matched
		res.matchedPolicy = matchedPolicy
		res.matchedNetwork = matchedNetwork
		res.matchedRule = matchedRule
	}()

	if lc.Policy == nil {
		return
	}

	do := func(policyUpstreams []string) {
		upstreams = append([]string(nil), policyUpstreams...)
	}

	var networkTargets []string
	var sourceIP net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		sourceIP = addr.IP
	case *net.TCPAddr:
		sourceIP = addr.IP
	}

networkRules:
	for _, rule := range lc.Policy.Networks {
		for source, targets := range rule {
			networkNum := strings.TrimPrefix(source, "network.")
			nc := p.cfg.Network[networkNum]
			if nc == nil {
				continue
			}
			for _, ipNet := range nc.IPNets {
				if ipNet.Contains(sourceIP) {
					matchedPolicy = lc.Policy.Name
					matchedNetwork = source
					networkTargets = targets
					matched = true
					break networkRules
				}
			}
		}
	}

macRules:
	for _, rule := range lc.Policy.Macs {
		for source, targets := range rule {
			if source != "" && (strings.EqualFold(source, srcMac) || wildcardMatches(strings.ToLower(source), strings.ToLower(srcMac))) {
				matchedPolicy = lc.Policy.Name
				matchedNetwork = source
				networkTargets = targets
				matched = true
				break macRules
			}
		}
	}

	for _, rule := range lc.Policy.Rules {
		// There's only one entry per rule, config validation ensures this.
		for source, targets := range rule {
			if source == domain || wildcardMatches(source, domain) {
				matchedPolicy = lc.Policy.Name
				if len(networkTargets) > 0 {
					matchedNetwork += " (unenforced)"
				}
				matchedRule = source
				do(targets)
				matched = true
				return
			}
		}
	}

	if matched {
		do(networkTargets)
	}

	return
}

func (p *prog) proxyPrivatePtrLookup(ctx context.Context, msg *dns.Msg) *dns.Msg {
	cDomainName := msg.Question[0].Name
	locked := p.ptrLoopGuard.TryLock(cDomainName)
	defer p.ptrLoopGuard.Unlock(cDomainName)
	if !locked {
		return nil
	}
	ip := ipFromARPA(cDomainName)
	if name := p.ciTable.LookupHostname(ip.String(), ""); name != "" {
		answer := new(dns.Msg)
		answer.SetReply(msg)
		answer.Compress = true
		answer.Answer = []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
			},
			Ptr: dns.Fqdn(name),
		}}
		ctrld.Log(ctx, p.Info(), "private PTR lookup, using client info table")
		ctrld.Log(ctx, p.Debug(), "client info: %v", ctrld.ClientInfo{
			Mac:      p.ciTable.LookupMac(ip.String()),
			IP:       ip.String(),
			Hostname: name,
		})
		return answer
	}
	return nil
}

func (p *prog) proxyLanHostnameQuery(ctx context.Context, msg *dns.Msg) *dns.Msg {
	q := msg.Question[0]
	hostname := strings.TrimSuffix(q.Name, ".")
	locked := p.lanLoopGuard.TryLock(hostname)
	defer p.lanLoopGuard.Unlock(hostname)
	if !locked {
		return nil
	}
	if ip := p.ciTable.LookupIPByHostname(hostname, q.Qtype == dns.TypeAAAA); ip != nil {
		answer := new(dns.Msg)
		answer.SetReply(msg)
		answer.Compress = true
		switch {
		case ip.Is4():
			answer.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(localTTL.Seconds()),
				},
				A: ip.AsSlice(),
			}}
		case ip.Is6():
			answer.Answer = []dns.RR{&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(localTTL.Seconds()),
				},
				AAAA: ip.AsSlice(),
			}}
		}
		ctrld.Log(ctx, p.Info(), "lan hostname lookup, using client info table")
		ctrld.Log(ctx, p.Debug(), "client info: %v", ctrld.ClientInfo{
			Mac:      p.ciTable.LookupMac(ip.String()),
			IP:       ip.String(),
			Hostname: hostname,
		})
		return answer
	}
	return nil
}

func (p *prog) proxy(ctx context.Context, req *proxyRequest) *proxyResponse {
	var staleAnswer *dns.Msg
	upstreams := req.ufr.upstreams
	serveStaleCache := p.cache != nil && p.cfg.Service.CacheServeStale
	upstreamConfigs := p.upstreamConfigsFromUpstreamNumbers(upstreams)

	if len(upstreamConfigs) == 0 {
		upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
		upstreams = []string{upstreamOS}
		// For OS resolver, local addresses are ignored to prevent possible looping.
		// However, on Active Directory Domain Controller, where it has local DNS server
		// running and listening on local addresses, these local addresses must be used
		// as nameservers, so queries for ADDC could be resolved as expected.
		if p.isAdDomainQuery(req.msg) {
			ctrld.Log(ctx, p.Debug(),
				"AD domain query detected for %s in domain %s",
				req.msg.Question[0].Name, p.adDomain)
			upstreamConfigs = []*ctrld.UpstreamConfig{localUpstreamConfig}
			upstreams = []string{upstreamOSLocal}
		}
	}

	res := &proxyResponse{}

	// LAN/PTR lookup flow:
	//
	// 1. If there's matching rule, follow it.
	// 2. Try from client info table.
	// 3. Try private resolver.
	// 4. Try remote upstream.
	isLanOrPtrQuery := false
	if req.ufr.matched {
		ctrld.Log(ctx, p.Debug(), "%s, %s, %s -> %v", req.ufr.matchedPolicy, req.ufr.matchedNetwork, req.ufr.matchedRule, upstreams)
	} else {
		switch {
		case isSrvLanLookup(req.msg):
			upstreams = []string{upstreamOS}
			upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
			ctx = ctrld.LanQueryCtx(ctx)
			ctrld.Log(ctx, p.Debug(), "SRV record lookup, using upstreams: %v", upstreams)
		case isPrivatePtrLookup(req.msg):
			isLanOrPtrQuery = true
			if answer := p.proxyPrivatePtrLookup(ctx, req.msg); answer != nil {
				res.answer = answer
				res.clientInfo = true
				return res
			}
			upstreams, upstreamConfigs = p.upstreamsAndUpstreamConfigForPtr(upstreams, upstreamConfigs)
			ctx = ctrld.LanQueryCtx(ctx)
			ctrld.Log(ctx, p.Debug(), "private PTR lookup, using upstreams: %v", upstreams)
		case isLanHostnameQuery(req.msg):
			isLanOrPtrQuery = true
			if answer := p.proxyLanHostnameQuery(ctx, req.msg); answer != nil {
				res.answer = answer
				res.clientInfo = true
				return res
			}
			upstreams = []string{upstreamOS}
			upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
			ctx = ctrld.LanQueryCtx(ctx)
			ctrld.Log(ctx, p.Debug(), "lan hostname lookup, using upstreams: %v", upstreams)
		default:
			ctrld.Log(ctx, p.Debug(), "no explicit policy matched, using default routing -> %v", upstreams)
		}
	}

	// Inverse query should not be cached: https://www.rfc-editor.org/rfc/rfc1035#section-7.4
	if p.cache != nil && req.msg.Question[0].Qtype != dns.TypePTR {
		for _, upstream := range upstreams {
			cachedValue := p.cache.Get(dnscache.NewKey(req.msg, upstream))
			if cachedValue == nil {
				continue
			}
			answer := cachedValue.Msg.Copy()
			ctrld.SetCacheReply(answer, req.msg, answer.Rcode)
			now := time.Now()
			if cachedValue.Expire.After(now) {
				ctrld.Log(ctx, p.Debug(), "hit cached response")
				setCachedAnswerTTL(answer, now, cachedValue.Expire)
				res.answer = answer
				res.cached = true
				return res
			}
			staleAnswer = answer
		}
	}
	resolve1 := func(upstream string, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) (*dns.Msg, error) {
		ctrld.Log(ctx, p.Debug(), "sending query to %s: %s", upstream, upstreamConfig.Name)
		dnsResolver, err := ctrld.NewResolver(ctx, upstreamConfig)
		if err != nil {
			ctrld.Log(ctx, p.Error().Err(err), "failed to create resolver")
			return nil, err
		}
		resolveCtx, cancel := upstreamConfig.Context(ctx)
		defer cancel()
		return dnsResolver.Resolve(resolveCtx, msg)
	}
	resolve := func(upstream string, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) *dns.Msg {
		if upstreamConfig.UpstreamSendClientInfo() && req.ci != nil {
			ctrld.Log(ctx, p.Debug(), "including client info with the request")
			ctx = context.WithValue(ctx, ctrld.ClientInfoCtxKey{}, req.ci)
		}
		answer, err := resolve1(upstream, upstreamConfig, msg)
		// if we have an answer, we should reset the failure count
		// we dont use reset here since we dont want to prevent failure counts from being incremented
		if answer != nil {
			p.um.mu.Lock()
			p.um.failureReq[upstream] = 0
			p.um.down[upstream] = false
			p.um.mu.Unlock()
			return answer
		}

		ctrld.Log(ctx, p.Error().Err(err), "failed to resolve query")

		// increase failure count when there is no answer
		// rehardless of what kind of error we get
		p.um.increaseFailureCount(upstream)

		if err != nil {
			// For timeout error (i.e: context deadline exceed), force re-bootstrapping.
			var e net.Error
			if errors.As(err, &e) && e.Timeout() {
				upstreamConfig.ReBootstrap(ctx)
			}
			// For network error, turn ipv6 off if enabled.
			if ctrld.HasIPv6(ctx) && (errUrlNetworkError(err) || errNetworkError(err)) {
				ctrld.DisableIPv6(ctx)
			}
		}

		return nil
	}
	for n, upstreamConfig := range upstreamConfigs {
		if upstreamConfig == nil {
			continue
		}
		logger := p.Debug().
			Str("upstream", upstreamConfig.String()).
			Str("query", req.msg.Question[0].Name).
			Bool("is_ad_query", p.isAdDomainQuery(req.msg)).
			Bool("is_lan_query", isLanOrPtrQuery)

		if p.isLoop(upstreamConfig) {
			ctrld.Log(ctx, logger, "DNS loop detected")
			continue
		}
		answer := resolve(upstreams[n], upstreamConfig, req.msg)
		if answer == nil {
			if serveStaleCache && staleAnswer != nil {
				ctrld.Log(ctx, p.Debug(), "serving stale cached response")
				now := time.Now()
				setCachedAnswerTTL(staleAnswer, now, now.Add(staleTTL))
				res.answer = staleAnswer
				res.cached = true
				return res
			}
			continue
		}
		// We are doing LAN/PTR lookup using private resolver, so always process next one.
		// Except for the last, we want to send response instead of saying all upstream failed.
		if answer.Rcode != dns.RcodeSuccess && isLanOrPtrQuery && n != len(upstreamConfigs)-1 {
			ctrld.Log(ctx, p.Debug(), "no response from %s, process to next upstream", upstreams[n])
			continue
		}
		if answer.Rcode != dns.RcodeSuccess && len(upstreamConfigs) > 1 && containRcode(req.failoverRcodes, answer.Rcode) {
			ctrld.Log(ctx, p.Debug(), "failover rcode matched, process to next upstream")
			continue
		}

		// set compression, as it is not set by default when unpacking
		answer.Compress = true

		if p.cache != nil && req.msg.Question[0].Qtype != dns.TypePTR {
			ttl := ttlFromMsg(answer)
			now := time.Now()
			expired := now.Add(time.Duration(ttl) * time.Second)
			if cachedTTL := p.cfg.Service.CacheTTLOverride; cachedTTL > 0 {
				expired = now.Add(time.Duration(cachedTTL) * time.Second)
			}
			setCachedAnswerTTL(answer, now, expired)
			p.cache.Add(dnscache.NewKey(req.msg, upstreams[n]), dnscache.NewValue(answer, expired))
			ctrld.Log(ctx, p.Debug(), "add cached response")
		}
		hostname := ""
		if req.ci != nil {
			hostname = req.ci.Hostname
		}
		ctrld.Log(ctx, p.Info(), "REPLY: %s -> %s (%s): %s", upstreams[n], req.ufr.srcAddr, hostname, dns.RcodeToString[answer.Rcode])
		res.answer = answer
		res.upstream = upstreamConfig.Endpoint
		return res
	}
	ctrld.Log(ctx, p.Error(), "all %v endpoints failed", upstreams)

	// if we have no healthy upstreams, trigger recovery flow
	if p.leakOnUpstreamFailure() {
		if p.um.countHealthy(upstreams) == 0 {
			p.recoveryCancelMu.Lock()
			if p.recoveryCancel == nil {
				var reason RecoveryReason
				if upstreams[0] == upstreamOS {
					reason = RecoveryReasonOSFailure
				} else {
					reason = RecoveryReasonRegularFailure
				}
				p.Debug().Msgf("No healthy upstreams, triggering recovery with reason: %v", reason)
				go p.handleRecovery(reason)
			} else {
				p.Debug().Msg("Recovery already in progress; skipping duplicate trigger from down detection")
			}
			p.recoveryCancelMu.Unlock()
		} else {
			p.Debug().Msg("One upstream is down but at least one is healthy; skipping recovery trigger")
		}

		// attempt query to OS resolver while as a retry catch all
		// we dont want this to happen if leakOnUpstreamFailure is false
		if upstreams[0] != upstreamOS {
			ctrld.Log(ctx, p.Debug(), "attempting query to OS resolver as a retry catch all")
			answer := resolve(upstreamOS, osUpstreamConfig, req.msg)
			if answer != nil {
				ctrld.Log(ctx, p.Debug(), "OS resolver retry query successful")
				res.answer = answer
				res.upstream = osUpstreamConfig.Endpoint
				return res
			}
			ctrld.Log(ctx, p.Debug(), "OS resolver retry query failed")
		}
	}

	answer := new(dns.Msg)
	answer.SetRcode(req.msg, dns.RcodeServerFailure)
	res.answer = answer
	return res
}

func (p *prog) upstreamsAndUpstreamConfigForPtr(upstreams []string, upstreamConfigs []*ctrld.UpstreamConfig) ([]string, []*ctrld.UpstreamConfig) {
	if len(p.localUpstreams) > 0 {
		tmp := make([]string, 0, len(p.localUpstreams)+len(upstreams))
		tmp = append(tmp, p.localUpstreams...)
		tmp = append(tmp, upstreams...)
		return tmp, p.upstreamConfigsFromUpstreamNumbers(tmp)
	}
	return append([]string{upstreamOS}, upstreams...), append([]*ctrld.UpstreamConfig{privateUpstreamConfig}, upstreamConfigs...)
}

func (p *prog) upstreamConfigsFromUpstreamNumbers(upstreams []string) []*ctrld.UpstreamConfig {
	upstreamConfigs := make([]*ctrld.UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		upstreamNum := strings.TrimPrefix(upstream, upstreamPrefix)
		upstreamConfigs = append(upstreamConfigs, p.cfg.Upstream[upstreamNum])
	}
	return upstreamConfigs
}

func (p *prog) isAdDomainQuery(msg *dns.Msg) bool {
	if p.adDomain == "" {
		return false
	}
	cDomainName := canonicalName(msg.Question[0].Name)
	return dns.IsSubDomain(p.adDomain, cDomainName)
}

// canonicalName returns canonical name from FQDN with "." trimmed.
func canonicalName(fqdn string) string {
	q := strings.TrimSpace(fqdn)
	q = strings.TrimSuffix(q, ".")
	// https://datatracker.ietf.org/doc/html/rfc4343
	q = strings.ToLower(q)

	return q
}

// wildcardMatches reports whether string str matches the wildcard pattern in case-insensitive manner.
func wildcardMatches(wildcard, str string) bool {
	// Wildcard match.
	wildCardParts := strings.Split(strings.ToLower(wildcard), "*")
	if len(wildCardParts) != 2 {
		return false
	}

	str = strings.ToLower(str)
	switch {
	case len(wildCardParts[0]) > 0 && len(wildCardParts[1]) > 0:
		// Domain must match both prefix and suffix.
		return strings.HasPrefix(str, wildCardParts[0]) && strings.HasSuffix(str, wildCardParts[1])

	case len(wildCardParts[1]) > 0:
		// Only suffix must match.
		return strings.HasSuffix(str, wildCardParts[1])

	case len(wildCardParts[0]) > 0:
		// Only prefix must match.
		return strings.HasPrefix(str, wildCardParts[0])
	}

	return false
}

func fmtRemoteToLocal(listenerNum, hostname, remote string) string {
	return fmt.Sprintf("%s (%s) -> listener.%s", remote, hostname, listenerNum)
}

func requestID() string {
	b := make([]byte, 3) // 6 chars
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func containRcode(rcodes []int, rcode int) bool {
	for i := range rcodes {
		if rcodes[i] == rcode {
			return true
		}
	}
	return false
}

func setCachedAnswerTTL(answer *dns.Msg, now, expiredTime time.Time) {
	ttlSecs := expiredTime.Sub(now).Seconds()
	if ttlSecs < 0 {
		return
	}

	ttl := uint32(ttlSecs)
	for _, rr := range answer.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range answer.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range answer.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

func ttlFromMsg(msg *dns.Msg) uint32 {
	for _, rr := range msg.Answer {
		return rr.Header().Ttl
	}
	for _, rr := range msg.Ns {
		return rr.Header().Ttl
	}
	return 0
}

func needLocalIPv6Listener() bool {
	// On Windows, there's no easy way for disabling/removing IPv6 DNS resolver, so we check whether we can
	// listen on ::1, then spawn a listener for receiving DNS requests.
	return ctrldnet.SupportsIPv6ListenLocal() && runtime.GOOS == "windows"
}

// ipAndMacFromMsg extracts IP and MAC information included in a DNS message, if any.
func ipAndMacFromMsg(msg *dns.Msg) (string, string) {
	ip, mac := "", ""
	if opt := msg.IsEdns0(); opt != nil {
		for _, s := range opt.Option {
			switch e := s.(type) {
			case *dns.EDNS0_LOCAL:
				if e.Code == EDNS0_OPTION_MAC {
					mac = net.HardwareAddr(e.Data).String()
				}
			case *dns.EDNS0_SUBNET:
				if len(e.Address) > 0 && !e.Address.IsLoopback() {
					ip = e.Address.String()
				}
			}
		}
	}
	return ip, mac
}

// stripClientSubnet removes EDNS0_SUBNET from DNS message if the IP is RFC1918 or loopback address,
// passing them to upstream is pointless, these cannot be used by anything on the WAN.
func stripClientSubnet(msg *dns.Msg) {
	if opt := msg.IsEdns0(); opt != nil {
		opts := make([]dns.EDNS0, 0, len(opt.Option))
		for _, s := range opt.Option {
			if e, ok := s.(*dns.EDNS0_SUBNET); ok && (e.Address.IsPrivate() || e.Address.IsLoopback()) {
				continue
			}
			opts = append(opts, s)
		}
		if len(opts) != len(opt.Option) {
			opt.Option = opts
		}
	}
}

func spoofRemoteAddr(addr net.Addr, ci *ctrld.ClientInfo) net.Addr {
	if ci != nil && ci.IP != "" {
		switch addr := addr.(type) {
		case *net.UDPAddr:
			udpAddr := &net.UDPAddr{
				IP:   net.ParseIP(ci.IP),
				Port: addr.Port,
				Zone: addr.Zone,
			}
			return udpAddr
		case *net.TCPAddr:
			udpAddr := &net.TCPAddr{
				IP:   net.ParseIP(ci.IP),
				Port: addr.Port,
				Zone: addr.Zone,
			}
			return udpAddr
		}
	}
	return addr
}

// runDNSServer starts a DNS server for given address and network,
// with the given handler. It ensures the server has started listening.
// Any error will be reported to the caller via returned channel.
//
// It's the caller responsibility to call Shutdown to close the server.
func runDNSServer(addr, network string, handler dns.Handler) (*dns.Server, <-chan error) {
	s := &dns.Server{
		Addr:    addr,
		Net:     network,
		Handler: handler,
	}

	startedCh := make(chan struct{})
	s.NotifyStartedFunc = func() { sync.OnceFunc(func() { close(startedCh) })() }

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		if err := s.ListenAndServe(); err != nil {
			s.NotifyStartedFunc()
			mainLog.Load().Error().Err(err).Msgf("could not listen and serve on: %s", s.Addr)
			errCh <- err
		}
	}()
	<-startedCh
	return s, errCh
}

func (p *prog) getClientInfo(remoteIP string, msg *dns.Msg) *ctrld.ClientInfo {
	ci := &ctrld.ClientInfo{}
	if p.appCallback != nil {
		ci.IP = p.appCallback.LanIp()
		ci.Mac = p.appCallback.MacAddress()
		ci.Hostname = p.appCallback.HostName()
		ci.Self = true
		return ci
	}
	ci.IP, ci.Mac = ipAndMacFromMsg(msg)
	switch {
	case ci.IP != "" && ci.Mac != "":
		// Nothing to do.
	case ci.IP == "" && ci.Mac != "":
		// Have MAC, no IP.
		ci.IP = p.ciTable.LookupIP(ci.Mac)
	case ci.IP == "" && ci.Mac == "":
		// Have nothing, use remote IP then lookup MAC.
		ci.IP = remoteIP
		fallthrough
	case ci.IP != "" && ci.Mac == "":
		// Have IP, no MAC.
		ci.Mac = p.ciTable.LookupMac(ci.IP)
	}

	// If MAC is still empty here, that mean the requests are made from virtual interface,
	// like VPN/Wireguard clients, so we use ci.IP as hostname to distinguish those clients.
	if ci.Mac == "" {
		if hostname := p.ciTable.LookupHostname(ci.IP, ""); hostname != "" {
			ci.Hostname = hostname
		} else {
			// Only use IP as hostname for IPv4 clients.
			// For Android devices, when it joins the network, it uses ctrld to resolve
			// its private DNS once and never reaches ctrld again. For each time, it uses
			// a different IPv6 address, which causes hundreds/thousands different client
			// IDs created for the same device, which is pointless.
			//
			// TODO(cuonglm): investigate whether this can be a false positive for other clients?
			if !ctrldnet.IsIPv6(ci.IP) {
				ci.Hostname = ci.IP
				p.ciTable.StoreVPNClient(ci)
			}
		}
	} else {
		ci.Hostname = p.ciTable.LookupHostname(ci.IP, ci.Mac)
	}
	ci.Self = p.queryFromSelf(ci.IP)
	// If this is a query from self, but ci.IP is not loopback IP,
	// try using hostname mapping for lookback IP if presents.
	if ci.Self {
		if name := p.ciTable.LocalHostname(); name != "" {
			ci.Hostname = name
		}
	}
	p.spoofLoopbackIpInClientInfo(ci)
	return ci
}

// spoofLoopbackIpInClientInfo replaces loopback IPs in client info.
//
// - Preference IPv4.
// - Preference RFC1918.
func (p *prog) spoofLoopbackIpInClientInfo(ci *ctrld.ClientInfo) {
	if ip := net.ParseIP(ci.IP); ip == nil || !ip.IsLoopback() {
		return
	}
	if ip := p.ciTable.LookupRFC1918IPv4(ci.Mac); ip != "" {
		ci.IP = ip
	}
}

// doSelfUninstall performs self-uninstall if these condition met:
//
// - There is only 1 ControlD upstream in-use.
// - Number of refused queries seen so far equals to selfUninstallMaxQueries.
// - The cdUID is deleted.
func (p *prog) doSelfUninstall(pr *proxyResponse) {
	answer := pr.answer
	if pr.refused || !p.canSelfUninstall.Load() || answer == nil || answer.Rcode != dns.RcodeRefused {
		return
	}

	p.selfUninstallMu.Lock()
	defer p.selfUninstallMu.Unlock()
	if p.checkingSelfUninstall {
		return
	}

	logger := p.logger.Load().With().Str("mode", "self-uninstall").Logger()
	if p.refusedQueryCount > selfUninstallMaxQueries {
		p.checkingSelfUninstall = true
		loggerCtx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
		_, err := controld.FetchResolverConfig(loggerCtx, cdUID, rootCmd.Version, cdDev)
		logger.Debug().Msg("maximum number of refused queries reached, checking device status")
		selfUninstallCheck(err, p, logger)

		if err != nil {
			logger.Warn().Err(err).Msg("could not fetch resolver config")
		}
		// Cool-of period to prevent abusing the API.
		go p.selfUninstallCoolOfPeriod()
		return
	}
	p.refusedQueryCount++
}

// selfUninstallCoolOfPeriod waits for 30 minutes before
// calling API again for checking ControlD device status.
func (p *prog) selfUninstallCoolOfPeriod() {
	t := time.NewTimer(time.Minute * 30)
	defer t.Stop()
	<-t.C
	p.selfUninstallMu.Lock()
	p.checkingSelfUninstall = false
	p.refusedQueryCount = 0
	p.selfUninstallMu.Unlock()
}

// forceFetchingAPI sends signal to force syncing API config if run in cd mode,
// and the domain == "cdUID.verify.controld.com"
func (p *prog) forceFetchingAPI(domain string) {
	if cdUID == "" {
		return
	}
	resolverID, parent, _ := strings.Cut(domain, ".")
	if resolverID != cdUID {
		return
	}
	switch {
	case cdDev && parent == "verify.controld.dev":
		// match ControlD dev
	case parent == "verify.controld.com":
		// match ControlD
	default:
		return
	}
	_ = p.apiForceReloadGroup.DoChan("force_sync_api", func() (interface{}, error) {
		p.apiForceReloadCh <- struct{}{}
		// Wait here to prevent abusing API if we are flooded.
		time.Sleep(timeDurationOrDefault(p.cfg.Service.ForceRefetchWaitTime, 30) * time.Second)
		return nil, nil
	})
}

// timeDurationOrDefault returns time duration value from n if not nil.
// Otherwise, it returns time duration value defaultN.
func timeDurationOrDefault(n *int, defaultN int) time.Duration {
	if n != nil && *n > 0 {
		return time.Duration(*n)
	}
	return time.Duration(defaultN)
}

// queryFromSelf reports whether the input IP is from device running ctrld.
func (p *prog) queryFromSelf(ip string) bool {
	if val, ok := p.queryFromSelfMap.Load(ip); ok {
		return val.(bool)
	}
	netIP := netip.MustParseAddr(ip)
	regularIPs, loopbackIPs, err := netmon.LocalAddresses()
	if err != nil {
		p.Warn().Err(err).Msg("could not get local addresses")
		return false
	}
	for _, localIP := range slices.Concat(regularIPs, loopbackIPs) {
		if localIP.Compare(netIP) == 0 {
			p.queryFromSelfMap.Store(ip, true)
			return true
		}
	}
	p.queryFromSelfMap.Store(ip, false)
	return false
}

// needRFC1918Listeners reports whether ctrld need to spawn listener for RFC 1918 addresses.
// This is helpful for non-desktop platforms to receive queries from LAN clients.
func needRFC1918Listeners(lc *ctrld.ListenerConfig) bool {
	return lc.IP == "127.0.0.1" && lc.Port == 53 && !ctrld.IsDesktopPlatform()
}

// ipFromARPA parses a FQDN arpa domain and return the IP address if valid.
func ipFromARPA(arpa string) net.IP {
	if arpa, ok := strings.CutSuffix(arpa, ".in-addr.arpa."); ok {
		if ptrIP := net.ParseIP(arpa); ptrIP != nil {
			return net.IP{ptrIP[15], ptrIP[14], ptrIP[13], ptrIP[12]}
		}
	}
	if arpa, ok := strings.CutSuffix(arpa, ".ip6.arpa."); ok {
		l := net.IPv6len * 2
		base := 16
		ip := make(net.IP, net.IPv6len)
		for i := 0; i < l && arpa != ""; i++ {
			idx := strings.LastIndexByte(arpa, '.')
			off := idx + 1
			if idx == -1 {
				idx = 0
				off = 0
			} else if idx == len(arpa)-1 {
				return nil
			}
			n, err := strconv.ParseUint(arpa[off:], base, 8)
			if err != nil {
				return nil
			}
			b := byte(n)
			ii := i / 2
			if i&1 == 1 {
				b |= ip[ii] << 4
			}
			ip[ii] = b
			arpa = arpa[:idx]
		}
		return ip
	}
	return nil
}

// isPrivatePtrLookup reports whether DNS message is an PTR query for LAN/CGNAT network.
func isPrivatePtrLookup(m *dns.Msg) bool {
	if m == nil || len(m.Question) == 0 {
		return false
	}
	q := m.Question[0]
	if ip := ipFromARPA(q.Name); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			return addr.IsPrivate() ||
				addr.IsLoopback() ||
				addr.IsLinkLocalUnicast() ||
				tsaddr.CGNATRange().Contains(addr)
		}
	}
	return false
}

// isLanHostnameQuery reports whether DNS message is an A/AAAA query with LAN hostname.
func isLanHostnameQuery(m *dns.Msg) bool {
	if m == nil || len(m.Question) == 0 {
		return false
	}
	q := m.Question[0]
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return false
	}
	return isLanHostname(q.Name)
}

// isSrvLanLookup reports whether DNS message is an SRV query of a LAN hostname.
func isSrvLanLookup(m *dns.Msg) bool {
	if m == nil || len(m.Question) == 0 {
		return false
	}
	q := m.Question[0]
	return q.Qtype == dns.TypeSRV && isLanHostname(q.Name)
}

// isLanHostname reports whether name is a LAN hostname.
func isLanHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	return !strings.Contains(name, ".") ||
		strings.HasSuffix(name, ".domain") ||
		strings.HasSuffix(name, ".lan") ||
		strings.HasSuffix(name, ".local")
}

// isWanClient reports whether the input is a WAN address.
func isWanClient(na net.Addr) bool {
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(na.String()); err == nil {
		ip = ap.Addr()
	}
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!tsaddr.CGNATRange().Contains(ip)
}

// resolveInternalDomainTestQuery resolves internal test domain query, returning the answer to the caller.
func resolveInternalDomainTestQuery(ctx context.Context, domain string, m *dns.Msg) *dns.Msg {
	logger := ctrld.LoggerFromCtx(ctx)
	ctrld.Log(ctx, logger.Debug(), "internal domain test query")

	q := m.Question[0]
	answer := new(dns.Msg)
	rrStr := fmt.Sprintf("%s A %s", domain, net.IPv4zero)
	if q.Qtype == dns.TypeAAAA {
		rrStr = fmt.Sprintf("%s AAAA %s", domain, net.IPv6zero)
	}
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		answer.Answer = append(answer.Answer, rr)
	}
	answer.SetReply(m)
	return answer
}

// FlushDNSCache flushes the DNS cache on macOS.
func FlushDNSCache() error {
	// if not macOS, return
	if runtime.GOOS != "darwin" {
		return nil
	}

	// Flush the DNS cache via mDNSResponder.
	// This is typically needed on modern macOS systems.
	if out, err := exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush mDNSResponder: %w, output: %s", err, string(out))
	}

	// Optionally, flush the directory services cache.
	if out, err := exec.Command("dscacheutil", "-flushcache").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush dscacheutil: %w, output: %s", err, string(out))
	}

	return nil
}

// monitorNetworkChanges starts monitoring for network interface changes
func (p *prog) monitorNetworkChanges(ctx context.Context) error {
	mon, err := netmon.New(func(format string, args ...any) {
		// Always fetch the latest logger (and inject the prefix)
		p.logger.Load().Printf("netmon: "+format, args...)
	})
	if err != nil {
		return fmt.Errorf("creating network monitor: %w", err)
	}

	mon.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		// Get map of valid interfaces
		validIfaces := validInterfacesMap(ctrld.LoggerCtx(ctx, p.logger.Load()))

		isMajorChange := mon.IsMajorChangeFrom(delta.Old, delta.New)

		p.Debug().
			Interface("old_state", delta.Old).
			Interface("new_state", delta.New).
			Bool("is_major_change", isMajorChange).
			Msg("Network change detected")

		changed := false
		activeInterfaceExists := false
		var changeIPs []netip.Prefix
		// Check each valid interface for changes
		for ifaceName := range validIfaces {
			oldIface, oldExists := delta.Old.Interface[ifaceName]
			newIface, newExists := delta.New.Interface[ifaceName]
			if !newExists {
				continue
			}

			oldIPs := delta.Old.InterfaceIPs[ifaceName]
			newIPs := delta.New.InterfaceIPs[ifaceName]

			// if a valid interface did not exist in old
			// check that its up and has usable IPs
			if !oldExists {
				// The interface is new (was not present in the old state).
				usableNewIPs := filterUsableIPs(newIPs)
				if newIface.IsUp() && len(usableNewIPs) > 0 {
					changed = true
					changeIPs = usableNewIPs
					p.Debug().
						Str("interface", ifaceName).
						Interface("new_ips", usableNewIPs).
						Msg("Interface newly appeared (was not present in old state)")
					break
				}
				continue
			}

			// Filter new IPs to only those that are usable.
			usableNewIPs := filterUsableIPs(newIPs)

			// Check if interface is up and has usable IPs.
			if newIface.IsUp() && len(usableNewIPs) > 0 {
				activeInterfaceExists = true
			}

			// Compare interface states and IPs (interfaceIPsEqual will itself filter the IPs).
			if !interfaceStatesEqual(&oldIface, &newIface) || !interfaceIPsEqual(oldIPs, newIPs) {
				if newIface.IsUp() && len(usableNewIPs) > 0 {
					changed = true
					changeIPs = usableNewIPs
					p.Debug().
						Str("interface", ifaceName).
						Interface("old_ips", oldIPs).
						Interface("new_ips", usableNewIPs).
						Msg("Interface state or IPs changed")
					break
				}
			}
		}

		// if the default route changed, set changed to true
		if delta.New.DefaultRouteInterface != delta.Old.DefaultRouteInterface {
			changed = true
			p.Debug().Msgf("Default route changed from %s to %s", delta.Old.DefaultRouteInterface, delta.New.DefaultRouteInterface)
		}

		if !changed {
			p.Debug().Msg("Ignoring interface change - no valid interfaces affected")
			// check if the default IPs are still on an interface that is up
			ValidateDefaultLocalIPsFromDelta(delta.New)
			return
		}

		if !activeInterfaceExists {
			p.Debug().Msg("No active interfaces found, skipping reinitialization")
			return
		}

		// Get IPs from default route interface in new state
		selfIP := p.defaultRouteIP()

		// Ensure that selfIP is an IPv4 address.
		// If defaultRouteIP mistakenly returns an IPv6 (such as a ULA), clear it
		if ip := net.ParseIP(selfIP); ip != nil && ip.To4() == nil {
			p.Debug().Msgf("defaultRouteIP returned a non-IPv4 address: %s, ignoring it", selfIP)
			selfIP = ""
		}
		var ipv6 string

		if delta.New.DefaultRouteInterface != "" {
			p.Debug().Msgf("default route interface: %s, IPs: %v", delta.New.DefaultRouteInterface, delta.New.InterfaceIPs[delta.New.DefaultRouteInterface])
			for _, ip := range delta.New.InterfaceIPs[delta.New.DefaultRouteInterface] {
				ipAddr, _ := netip.ParsePrefix(ip.String())
				addr := ipAddr.Addr()
				if selfIP == "" && addr.Is4() {
					p.Debug().Msgf("checking IP: %s", addr.String())
					if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
						selfIP = addr.String()
					}
				}
				if addr.Is6() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
					ipv6 = addr.String()
				}
			}
		} else {
			// If no default route interface is set yet, use the changed IPs
			p.Debug().Msgf("no default route interface found, using changed IPs: %v", changeIPs)
			for _, ip := range changeIPs {
				ipAddr, _ := netip.ParsePrefix(ip.String())
				addr := ipAddr.Addr()
				if selfIP == "" && addr.Is4() {
					p.Debug().Msgf("checking IP: %s", addr.String())
					if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
						selfIP = addr.String()
					}
				}
				if addr.Is6() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
					ipv6 = addr.String()
				}
			}
		}

		// Only set the IPv4 default if selfIP is a valid IPv4 address.
		if ip := net.ParseIP(selfIP); ip != nil && ip.To4() != nil {
			ctrld.SetDefaultLocalIPv4(ctrld.LoggerCtx(ctx, p.logger.Load()), ip)
			if !isMobile() && p.ciTable != nil {
				p.ciTable.SetSelfIP(selfIP)
			}
		}
		if ip := net.ParseIP(ipv6); ip != nil {
			ctrld.SetDefaultLocalIPv6(ctrld.LoggerCtx(ctx, p.logger.Load()), ip)
		}
		p.Debug().Msgf("Set default local IPv4: %s, IPv6: %s", selfIP, ipv6)

		p.handleRecovery(RecoveryReasonNetworkChange)
	})

	mon.Start()
	p.Debug().Msg("Network monitor started")
	return nil
}

// interfaceStatesEqual compares two interface states
func interfaceStatesEqual(a, b *netmon.Interface) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IsUp() == b.IsUp()
}

// filterUsableIPs is a helper that returns only "usable" IP prefixes,
// filtering out link-local, loopback, multicast, unspecified, broadcast, or CGNAT addresses.
func filterUsableIPs(prefixes []netip.Prefix) []netip.Prefix {
	var usable []netip.Prefix
	for _, p := range prefixes {
		addr := p.Addr()
		if addr.IsLinkLocalUnicast() ||
			addr.IsLoopback() ||
			addr.IsMulticast() ||
			addr.IsUnspecified() ||
			addr.IsLinkLocalMulticast() ||
			(addr.Is4() && addr.String() == "255.255.255.255") ||
			tsaddr.CGNATRange().Contains(addr) {
			continue
		}
		usable = append(usable, p)
	}
	return usable
}

// Modified interfaceIPsEqual compares only the usable (non-link local, non-loopback, etc.) IP addresses.
func interfaceIPsEqual(a, b []netip.Prefix) bool {
	aUsable := filterUsableIPs(a)
	bUsable := filterUsableIPs(b)
	if len(aUsable) != len(bUsable) {
		return false
	}

	aMap := make(map[string]bool)
	for _, ip := range aUsable {
		aMap[ip.String()] = true
	}
	for _, ip := range bUsable {
		if !aMap[ip.String()] {
			return false
		}
	}
	return true
}

// checkUpstreamOnce sends a test query to the specified upstream.
// Returns nil if the upstream responds successfully.
func (p *prog) checkUpstreamOnce(upstream string, uc *ctrld.UpstreamConfig) error {
	p.Debug().Msgf("Starting check for upstream: %s", upstream)

	resolver, err := ctrld.NewResolver(ctrld.LoggerCtx(context.Background(), p.logger.Load()), uc)
	if err != nil {
		p.Error().Err(err).Msgf("Failed to create resolver for upstream %s", upstream)
		return err
	}

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	timeout := 1000 * time.Millisecond
	if uc.Timeout > 0 {
		timeout = time.Millisecond * time.Duration(uc.Timeout)
	}
	p.Debug().Msgf("Timeout for upstream %s: %s", upstream, timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	uc.ReBootstrap(ctrld.LoggerCtx(ctx, p.logger.Load()))
	p.Debug().Msgf("Rebootstrapping resolver for upstream: %s", upstream)

	start := time.Now()
	_, err = resolver.Resolve(ctx, msg)
	duration := time.Since(start)

	if err != nil {
		p.Error().Err(err).Msgf("Upstream %s check failed after %v", upstream, duration)
	} else {
		p.Debug().Msgf("Upstream %s responded successfully in %v", upstream, duration)
	}
	return err
}

// handleRecovery performs a unified recovery by removing DNS settings,
// canceling existing recovery checks for network changes, but coalescing duplicate
// upstream failure recoveries, waiting for recovery to complete (using a cancellable context without timeout),
// and then re-applying the DNS settings.
func (p *prog) handleRecovery(reason RecoveryReason) {
	p.Debug().Msg("Starting recovery process: removing DNS settings")

	// For network changes, cancel any existing recovery check because the network state has changed.
	if reason == RecoveryReasonNetworkChange {
		p.recoveryCancelMu.Lock()
		if p.recoveryCancel != nil {
			p.Debug().Msg("Cancelling existing recovery check (network change)")
			p.recoveryCancel()
			p.recoveryCancel = nil
		}
		p.recoveryCancelMu.Unlock()
	} else {
		// For upstream failures, if a recovery is already in progress, do nothing new.
		p.recoveryCancelMu.Lock()
		if p.recoveryCancel != nil {
			p.Debug().Msg("Upstream recovery already in progress; skipping duplicate trigger")
			p.recoveryCancelMu.Unlock()
			return
		}
		p.recoveryCancelMu.Unlock()
	}

	// Create a new recovery context without a fixed timeout.
	p.recoveryCancelMu.Lock()
	recoveryCtx, cancel := context.WithCancel(context.Background())
	p.recoveryCancel = cancel
	p.recoveryCancelMu.Unlock()

	// Immediately remove our DNS settings from the interface.
	// set recoveryRunning to true to prevent watchdogs from putting the listener back on the interface
	p.recoveryRunning.Store(true)
	// we do not want to restore any static DNS settings
	// we must try to get the DHCP values, any static DNS settings
	// will be appended to nameservers from the saved interface values
	p.resetDNS(false, false)

	loggerCtx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
	// For an OS failure, reinitialize OS resolver nameservers immediately.
	if reason == RecoveryReasonOSFailure {
		p.Debug().Msg("OS resolver failure detected; reinitializing OS resolver nameservers")
		ns := ctrld.InitializeOsResolver(loggerCtx, true)
		if len(ns) == 0 {
			p.Warn().Msg("No nameservers found for OS resolver; using existing values")
		} else {
			p.Info().Msgf("Reinitialized OS resolver with nameservers: %v", ns)
		}
	}

	// Build upstream map based on the recovery reason.
	upstreams := p.buildRecoveryUpstreams(reason)

	// Wait indefinitely until one of the upstreams recovers.
	recovered, err := p.waitForUpstreamRecovery(recoveryCtx, upstreams)
	if err != nil {
		p.Error().Err(err).Msg("Recovery canceled; DNS settings remain removed")
		p.recoveryCancelMu.Lock()
		p.recoveryCancel = nil
		p.recoveryCancelMu.Unlock()
		return
	}
	p.Info().Msgf("Upstream %q recovered; re-applying DNS settings", recovered)

	// reset the upstream failure count and down state
	p.um.reset(recovered)

	// For network changes we also reinitialize the OS resolver.
	if reason == RecoveryReasonNetworkChange {
		ns := ctrld.InitializeOsResolver(loggerCtx, true)
		if len(ns) == 0 {
			p.Warn().Msg("No nameservers found for OS resolver during network-change recovery; using existing values")
		} else {
			p.Info().Msgf("Reinitialized OS resolver with nameservers: %v", ns)
		}
	}

	// Apply our DNS settings back and log the interface state.
	p.setDNS()
	p.logInterfacesState()

	// allow watchdogs to put the listener back on the interface if its changed for any reason
	p.recoveryRunning.Store(false)

	// Clear the recovery cancellation for a clean slate.
	p.recoveryCancelMu.Lock()
	p.recoveryCancel = nil
	p.recoveryCancelMu.Unlock()
}

// waitForUpstreamRecovery checks the provided upstreams concurrently until one recovers.
// It returns the name of the recovered upstream or an error if the check times out.
func (p *prog) waitForUpstreamRecovery(ctx context.Context, upstreams map[string]*ctrld.UpstreamConfig) (string, error) {
	recoveredCh := make(chan string, 1)
	var wg sync.WaitGroup

	p.Debug().Msgf("Starting upstream recovery check for %d upstreams", len(upstreams))

	for name, uc := range upstreams {
		wg.Add(1)
		go func(name string, uc *ctrld.UpstreamConfig) {
			defer wg.Done()
			p.Debug().Msgf("Starting recovery check loop for upstream: %s", name)
			attempts := 0
			for {
				select {
				case <-ctx.Done():
					p.Debug().Msgf("Context canceled for upstream %s", name)
					return
				default:
					attempts++
					// checkUpstreamOnce will reset any failure counters on success.
					if err := p.checkUpstreamOnce(name, uc); err == nil {
						p.Debug().Msgf("Upstream %s recovered successfully", name)
						select {
						case recoveredCh <- name:
							p.Debug().Msgf("Sent recovery notification for upstream %s", name)
						default:
							p.Debug().Msg("Recovery channel full, another upstream already recovered")
						}
						return
					}
					p.Debug().Msgf("Upstream %s check failed, sleeping before retry", name)
					time.Sleep(checkUpstreamBackoffSleep)

					// if this is the upstreamOS and it's the 3rd attempt (or multiple of 3),
					// we should try to reinit the OS resolver to ensure we can recover
					if name == upstreamOS && attempts%3 == 0 {
						p.Debug().Msgf("UpstreamOS check failed on attempt %d, reinitializing OS resolver", attempts)
						ns := ctrld.InitializeOsResolver(ctrld.LoggerCtx(ctx, p.logger.Load()), true)
						if len(ns) == 0 {
							p.Warn().Msg("No nameservers found for OS resolver; using existing values")
						} else {
							p.Info().Msgf("Reinitialized OS resolver with nameservers: %v", ns)
						}
					}
				}
			}
		}(name, uc)
	}

	var recovered string
	select {
	case recovered = <-recoveredCh:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	wg.Wait()
	return recovered, nil
}

// buildRecoveryUpstreams constructs the map of upstream configurations to test.
// For OS failures we supply the manual OS resolver upstream configuration.
// For network change or regular failure we use the upstreams defined in p.cfg (ignoring OS).
func (p *prog) buildRecoveryUpstreams(reason RecoveryReason) map[string]*ctrld.UpstreamConfig {
	upstreams := make(map[string]*ctrld.UpstreamConfig)
	switch reason {
	case RecoveryReasonOSFailure:
		upstreams[upstreamOS] = osUpstreamConfig
	case RecoveryReasonNetworkChange, RecoveryReasonRegularFailure:
		// Use all configured upstreams except any OS type.
		for k, uc := range p.cfg.Upstream {
			if uc.Type != ctrld.ResolverTypeOS {
				upstreams[upstreamPrefix+k] = uc
			}
		}
	}
	return upstreams
}

// ValidateDefaultLocalIPsFromDelta checks if the default local IPv4 and IPv6 stored
// are still present in the new network state (provided by delta.New).
// If a stored default IP is no longer active, it resets that default (sets it to nil)
// so that it won't be used in subsequent custom dialer contexts.
func ValidateDefaultLocalIPsFromDelta(newState *netmon.State) {
	currentIPv4 := ctrld.GetDefaultLocalIPv4()
	currentIPv6 := ctrld.GetDefaultLocalIPv6()

	// Build a map of active IP addresses from the new state.
	activeIPs := make(map[string]bool)
	for _, prefixes := range newState.InterfaceIPs {
		for _, prefix := range prefixes {
			activeIPs[prefix.Addr().String()] = true
		}
	}

	// Check if the default IPv4 is still active.
	if currentIPv4 != nil && !activeIPs[currentIPv4.String()] {
		mainLog.Load().Debug().Msgf("DefaultLocalIPv4 %s is no longer active in the new state. Resetting.", currentIPv4)
		ctrld.SetDefaultLocalIPv4(ctrld.LoggerCtx(context.Background(), mainLog.Load()), nil)
	}

	// Check if the default IPv6 is still active.
	if currentIPv6 != nil && !activeIPs[currentIPv6.String()] {
		mainLog.Load().Debug().Msgf("DefaultLocalIPv6 %s is no longer active in the new state. Resetting.", currentIPv6)
		ctrld.SetDefaultLocalIPv6(ctrld.LoggerCtx(context.Background(), mainLog.Load()), nil)
	}
}

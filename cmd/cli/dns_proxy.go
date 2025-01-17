package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	Timeout: 2000,
}

var privateUpstreamConfig = &ctrld.UpstreamConfig{
	Name:    "Private resolver",
	Type:    ctrld.ResolverTypePrivate,
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
	cached     bool
	clientInfo bool
	upstream   string
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

func (p *prog) serveDNS(listenerNum string) error {
	listenerConfig := p.cfg.Listener[listenerNum]
	// make sure ip is allocated
	if allocErr := p.allocateIP(listenerConfig.IP); allocErr != nil {
		mainLog.Load().Error().Err(allocErr).Str("ip", listenerConfig.IP).Msg("serveUDP: failed to allocate listen ip")
		return allocErr
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		p.sema.acquire()
		defer p.sema.release()
		if len(m.Question) == 0 {
			answer := new(dns.Msg)
			answer.SetRcode(m, dns.RcodeFormatError)
			_ = w.WriteMsg(answer)
			return
		}
		listenerConfig := p.cfg.Listener[listenerNum]
		reqId := requestID()
		ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, reqId)
		if !listenerConfig.AllowWanClients && isWanClient(w.RemoteAddr()) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "query refused, listener does not allow WAN clients: %s", w.RemoteAddr().String())
			answer := new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)
			_ = w.WriteMsg(answer)
			return
		}
		go p.detectLoop(m)
		q := m.Question[0]
		domain := canonicalName(q.Name)
		if domain == selfCheckInternalTestDomain {
			answer := resolveInternalDomainTestQuery(ctx, domain, m)
			_ = w.WriteMsg(answer)
			return
		}
		if _, ok := p.cacheFlushDomainsMap[domain]; ok && p.cache != nil {
			p.cache.Purge()
			ctrld.Log(ctx, mainLog.Load().Debug(), "received query %q, local cache is purged", domain)
		}
		remoteIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		ci := p.getClientInfo(remoteIP, m)
		ci.ClientIDPref = p.cfg.Service.ClientIDPref
		stripClientSubnet(m)
		remoteAddr := spoofRemoteAddr(w.RemoteAddr(), ci)
		fmtSrcToDest := fmtRemoteToLocal(listenerNum, ci.Hostname, remoteAddr.String())
		t := time.Now()
		ctrld.Log(ctx, mainLog.Load().Info(), "QUERY: %s: %s %s", fmtSrcToDest, dns.TypeToString[q.Qtype], domain)
		ur := p.upstreamFor(ctx, listenerNum, listenerConfig, remoteAddr, ci.Mac, domain)

		labelValues := make([]string, 0, len(statsQueriesCountLabels))
		labelValues = append(labelValues, net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port)))
		labelValues = append(labelValues, ci.IP)
		labelValues = append(labelValues, ci.Mac)
		labelValues = append(labelValues, ci.Hostname)

		var answer *dns.Msg
		if !ur.matched && listenerConfig.Restricted {
			ctrld.Log(ctx, mainLog.Load().Info(), "query refused, %s does not match any network policy", remoteAddr.String())
			answer = new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)
			labelValues = append(labelValues, "") // no upstream
		} else {
			var failoverRcode []int
			if listenerConfig.Policy != nil {
				failoverRcode = listenerConfig.Policy.FailoverRcodeNumbers
			}
			pr := p.proxy(ctx, &proxyRequest{
				msg:            m,
				ci:             ci,
				failoverRcodes: failoverRcode,
				ufr:            ur,
			})
			go p.doSelfUninstall(pr.answer)

			answer = pr.answer
			rtt := time.Since(t)
			ctrld.Log(ctx, mainLog.Load().Debug(), "received response of %d bytes in %s", answer.Len(), rtt)
			upstream := pr.upstream
			switch {
			case pr.cached:
				upstream = "cache"
			case pr.clientInfo:
				upstream = "client_info_table"
			}
			labelValues = append(labelValues, upstream)
		}
		labelValues = append(labelValues, dns.TypeToString[q.Qtype])
		labelValues = append(labelValues, dns.RcodeToString[answer.Rcode])
		go func() {
			p.WithLabelValuesInc(statsQueriesCount, labelValues...)
			p.WithLabelValuesInc(statsClientQueriesCount, []string{ci.IP, ci.Mac, ci.Hostname}...)
			p.forceFetchingAPI(domain)
		}()
		if err := w.WriteMsg(answer); err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "serveDNS: failed to send DNS response to client")
		}
	})

	g, ctx := errgroup.WithContext(context.Background())
	for _, proto := range []string{"udp", "tcp"} {
		proto := proto
		if needLocalIPv6Listener() {
			g.Go(func() error {
				s, errCh := runDNSServer(net.JoinHostPort("::1", strconv.Itoa(listenerConfig.Port)), proto, handler)
				defer s.Shutdown()
				select {
				case <-p.stopCh:
				case <-ctx.Done():
				case err := <-errCh:
					// Local ipv6 listener should not terminate ctrld.
					// It's a workaround for a quirk on Windows.
					mainLog.Load().Warn().Err(err).Msg("local ipv6 listener failed")
				}
				return nil
			})
		}
		// When we spawn a listener on 127.0.0.1, also spawn listeners on the RFC1918
		// addresses of the machine. So ctrld could receive queries from LAN clients.
		if needRFC1918Listeners(listenerConfig) {
			g.Go(func() error {
				for _, addr := range ctrld.Rfc1918Addresses() {
					func() {
						listenAddr := net.JoinHostPort(addr, strconv.Itoa(listenerConfig.Port))
						s, errCh := runDNSServer(listenAddr, proto, handler)
						defer s.Shutdown()
						select {
						case <-p.stopCh:
						case <-ctx.Done():
						case err := <-errCh:
							// RFC1918 listener should not terminate ctrld.
							// It's a workaround for a quirk on system with systemd-resolved.
							mainLog.Load().Warn().Err(err).Msgf("could not listen on %s: %s", proto, listenAddr)
						}
					}()
				}
				return nil
			})
		}
		g.Go(func() error {
			addr := net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port))
			s, errCh := runDNSServer(addr, proto, handler)
			defer s.Shutdown()

			p.started <- struct{}{}

			select {
			case <-p.stopCh:
			case <-ctx.Done():
			case err := <-errCh:
				return err
			}
			return nil
		})
	}
	return g.Wait()
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
		ctrld.Log(ctx, mainLog.Load().Info(), "private PTR lookup, using client info table")
		ctrld.Log(ctx, mainLog.Load().Debug(), "client info: %v", ctrld.ClientInfo{
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
		ctrld.Log(ctx, mainLog.Load().Info(), "lan hostname lookup, using client info table")
		ctrld.Log(ctx, mainLog.Load().Debug(), "client info: %v", ctrld.ClientInfo{
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

	leaked := false
	// If ctrld is going to leak query to OS resolver, check remote upstream in background,
	// so ctrld could be back to normal operation as long as the network is back online.
	if len(upstreamConfigs) > 0 && p.leakingQuery.Load() {
		for n, uc := range upstreamConfigs {
			go p.checkUpstream(upstreams[n], uc)
		}
		upstreamConfigs = nil
		leaked = true
		ctrld.Log(ctx, mainLog.Load().Debug(), "%v is down, leaking query to OS resolver", upstreams)
	}

	if len(upstreamConfigs) == 0 {
		upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
		upstreams = []string{upstreamOS}
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
		if leaked {
			ctrld.Log(ctx, mainLog.Load().Debug(), "%s, %s, %s -> %v (leaked)", req.ufr.matchedPolicy, req.ufr.matchedNetwork, req.ufr.matchedRule, upstreams)
		} else {
			ctrld.Log(ctx, mainLog.Load().Debug(), "%s, %s, %s -> %v", req.ufr.matchedPolicy, req.ufr.matchedNetwork, req.ufr.matchedRule, upstreams)
		}
	} else {
		switch {
		case isPrivatePtrLookup(req.msg):
			isLanOrPtrQuery = true
			if answer := p.proxyPrivatePtrLookup(ctx, req.msg); answer != nil {
				res.answer = answer
				res.clientInfo = true
				return res
			}
			upstreams, upstreamConfigs = p.upstreamsAndUpstreamConfigForLanAndPtr(upstreams, upstreamConfigs)
			ctrld.Log(ctx, mainLog.Load().Debug(), "private PTR lookup, using upstreams: %v", upstreams)
		case isLanHostnameQuery(req.msg):
			isLanOrPtrQuery = true
			if answer := p.proxyLanHostnameQuery(ctx, req.msg); answer != nil {
				res.answer = answer
				res.clientInfo = true
				return res
			}
			upstreams, upstreamConfigs = p.upstreamsAndUpstreamConfigForLanAndPtr(upstreams, upstreamConfigs)
			ctrld.Log(ctx, mainLog.Load().Debug(), "lan hostname lookup, using upstreams: %v", upstreams)
		default:
			ctrld.Log(ctx, mainLog.Load().Debug(), "no explicit policy matched, using default routing -> %v", upstreams)
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
			answer.SetRcode(req.msg, answer.Rcode)
			now := time.Now()
			if cachedValue.Expire.After(now) {
				ctrld.Log(ctx, mainLog.Load().Debug(), "hit cached response")
				setCachedAnswerTTL(answer, now, cachedValue.Expire)
				res.answer = answer
				res.cached = true
				return res
			}
			staleAnswer = answer
		}
	}
	resolve1 := func(n int, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) (*dns.Msg, error) {
		ctrld.Log(ctx, mainLog.Load().Debug(), "sending query to %s: %s", upstreams[n], upstreamConfig.Name)
		dnsResolver, err := ctrld.NewResolver(upstreamConfig)
		if err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to create resolver")
			return nil, err
		}
		resolveCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		if upstreamConfig.Timeout > 0 {
			timeoutCtx, cancel := context.WithTimeout(resolveCtx, time.Millisecond*time.Duration(upstreamConfig.Timeout))
			defer cancel()
			resolveCtx = timeoutCtx
		}
		return dnsResolver.Resolve(resolveCtx, msg)
	}
	resolve := func(n int, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) *dns.Msg {
		if upstreamConfig.UpstreamSendClientInfo() && req.ci != nil {
			ctrld.Log(ctx, mainLog.Load().Debug(), "including client info with the request")
			ctx = context.WithValue(ctx, ctrld.ClientInfoCtxKey{}, req.ci)
		}
		answer, err := resolve1(n, upstreamConfig, msg)
		if err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to resolve query")
			isNetworkErr := errNetworkError(err)
			if isNetworkErr {
				p.um.increaseFailureCount(upstreams[n])
				if p.um.isDown(upstreams[n]) {
					go p.checkUpstream(upstreams[n], upstreamConfig)
				}
			}
			// For timeout error (i.e: context deadline exceed), force re-bootstrapping.
			var e net.Error
			if errors.As(err, &e) && e.Timeout() {
				upstreamConfig.ReBootstrap()
			}
			return nil
		}
		return answer
	}
	for n, upstreamConfig := range upstreamConfigs {
		if upstreamConfig == nil {
			continue
		}
		if p.isLoop(upstreamConfig) {
			mainLog.Load().Warn().Msgf("dns loop detected, upstream: %q, endpoint: %q", upstreamConfig.Name, upstreamConfig.Endpoint)
			continue
		}
		if p.um.isDown(upstreams[n]) {
			ctrld.Log(ctx, mainLog.Load().Warn(), "%s is down", upstreams[n])
			continue
		}
		answer := resolve(n, upstreamConfig, req.msg)
		if answer == nil {
			if serveStaleCache && staleAnswer != nil {
				ctrld.Log(ctx, mainLog.Load().Debug(), "serving stale cached response")
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
			ctrld.Log(ctx, mainLog.Load().Debug(), "no response from %s, process to next upstream", upstreams[n])
			continue
		}
		if answer.Rcode != dns.RcodeSuccess && len(upstreamConfigs) > 1 && containRcode(req.failoverRcodes, answer.Rcode) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "failover rcode matched, process to next upstream")
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
			ctrld.Log(ctx, mainLog.Load().Debug(), "add cached response")
		}
		hostname := ""
		if req.ci != nil {
			hostname = req.ci.Hostname
		}
		ctrld.Log(ctx, mainLog.Load().Info(), "REPLY: %s -> %s (%s): %s", upstreams[n], req.ufr.srcAddr, hostname, dns.RcodeToString[answer.Rcode])
		res.answer = answer
		res.upstream = upstreamConfig.Endpoint
		return res
	}
	ctrld.Log(ctx, mainLog.Load().Error(), "all %v endpoints failed", upstreams)
	if cdUID != "" && p.leakOnUpstreamFailure() {
		p.leakingQueryMu.Lock()
		if !p.leakingQueryWasRun {
			p.leakingQueryWasRun = true
			go p.performLeakingQuery()
		}
		p.leakingQueryMu.Unlock()
	}
	answer := new(dns.Msg)
	answer.SetRcode(req.msg, dns.RcodeServerFailure)
	res.answer = answer
	return res
}

func (p *prog) upstreamsAndUpstreamConfigForLanAndPtr(upstreams []string, upstreamConfigs []*ctrld.UpstreamConfig) ([]string, []*ctrld.UpstreamConfig) {
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
func (p *prog) doSelfUninstall(answer *dns.Msg) {
	if !p.canSelfUninstall.Load() || answer == nil || answer.Rcode != dns.RcodeRefused {
		return
	}

	p.selfUninstallMu.Lock()
	defer p.selfUninstallMu.Unlock()
	if p.checkingSelfUninstall {
		return
	}

	logger := mainLog.Load().With().Str("mode", "self-uninstall").Logger()
	if p.refusedQueryCount > selfUninstallMaxQueries {
		p.checkingSelfUninstall = true
		_, err := controld.FetchResolverConfig(cdUID, rootCmd.Version, cdDev)
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

// performLeakingQuery performs necessary works to leak queries to OS resolver.
func (p *prog) performLeakingQuery() {
	mainLog.Load().Warn().Msg("leaking query to OS resolver")
	// Signal dns watchers to stop, so changes made below won't be reverted.
	p.leakingQuery.Store(true)
	p.resetDNS()
	ns := ctrld.InitializeOsResolver()
	mainLog.Load().Debug().Msgf("re-initialized OS resolver with nameservers: %v", ns)
	p.dnsWg.Wait()
	p.setDNS()
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
		mainLog.Load().Warn().Err(err).Msg("could not get local addresses")
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

func needRFC1918Listeners(lc *ctrld.ListenerConfig) bool {
	return lc.IP == "127.0.0.1" && lc.Port == 53
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
	name := strings.TrimSuffix(q.Name, ".")
	return !strings.Contains(name, ".") ||
		strings.HasSuffix(name, ".domain") ||
		strings.HasSuffix(name, ".lan")
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
	ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain test query")

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

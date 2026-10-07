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
	"github.com/Control-D-Inc/ctrld/internal/router"
)

const (
	staleTTL = 60 * time.Second
	localTTL = 3600 * time.Second
	// zpaDNSEchoDomain is Zscaler Client Connector's fixed public health-check
	// name. Client Connector must see the answer to it arrive on its own DNS
	// path before it will synthesize addresses for Private Access applications.
	zpaDNSEchoDomain = "dnsechotest.zscaler.com"
	// zpaDNSEchoPolicyName is reported as the matched policy when the built-in
	// ZPA DNS echo bypass routes a query, so log lines name the reason.
	zpaDNSEchoPolicyName = "Built-in ZPA DNS echo bypass"
	// noRuleMatched is the matchedRule placeholder used when no listener domain
	// rule matched the query. It is compared, not only logged: the built-in ZPA
	// echo bypass yields to an explicit domain rule for the same name.
	noRuleMatched = "no rule"
	// EDNS0_OPTION_MAC is dnsmasq EDNS0 code for adding mac option.
	// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/dns-protocol.h;h=76ac66a8c28317e9c121a74ab5fd0e20f6237dc8;hb=HEAD#l81
	// This is also dns.EDNS0LOCALSTART, but define our own constant here for clarification.
	EDNS0_OPTION_MAC = 0xFDE9

	// selfUninstallMaxQueries is number of REFUSED queries seen before checking for self-uninstallation.
	selfUninstallMaxQueries = 32
)

// zpaDNSEchoBypassEnabled limits the built-in ZPA DNS echo bypass to macOS,
// the only platform where pf interception is known to break Zscaler Private
// Access. Tests override it.
var zpaDNSEchoBypassEnabled = runtime.GOOS == "darwin"

// zpaDNSEchoBypassActive reports whether the built-in Zscaler DNS echo bypass
// applies. Like every other VPN accommodation it is skipped in
// --intercept-mode hard, where the operator has asked for all DNS to go
// through ctrld with no split routing.
func zpaDNSEchoBypassActive() bool {
	return zpaDNSEchoBypassEnabled && dnsIntercept && !hardIntercept
}

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
	// zpaDNSEcho reports that the built-in Zscaler DNS echo bypass chose the
	// upstreams. proxy() keeps this query out of the response cache so Client
	// Connector's health check reaches the OS resolver on every poll.
	zpaDNSEcho bool
}

func (p *prog) addCachedResponse(key dnscache.Key, answer *dns.Msg) {
	ttl := ttlFromMsg(answer)
	now := time.Now()
	expired := now.Add(time.Duration(ttl) * time.Second)
	if cachedTTL := p.cfg.Service.CacheTTLOverride; cachedTTL > 0 {
		expired = now.Add(time.Duration(cachedTTL) * time.Second)
	}
	setCachedAnswerTTL(answer, now, expired)
	p.cache.Add(key, dnscache.NewValue(answer, expired))
}

func (p *prog) cachedResponse(req *dns.Msg, upstream string, dns64Prefix netip.Prefix, dns64Active bool, now time.Time) (answer, stale *dns.Msg, hit, dns64Hit, dns64Bypass bool) {
	if dns64Active && dns64RequestAllowed(req) {
		if cachedValue := p.cache.Get(dns64CacheKey(req, upstream, dns64Prefix)); cachedValue != nil {
			answer = cachedValue.Msg.Copy()
			ctrld.SetCacheReply(answer, req, answer.Rcode)
			if cachedValue.Expire.After(now) {
				setCachedAnswerTTL(answer, now, cachedValue.Expire)
				return answer, nil, true, true, false
			}
			stale = answer
		}
	}

	cachedValue := p.cache.Get(dnscache.NewKey(req, upstream))
	if cachedValue == nil {
		return nil, stale, false, false, false
	}
	answer = cachedValue.Msg.Copy()
	ctrld.SetCacheReply(answer, req, answer.Rcode)
	if cachedValue.Expire.After(now) {
		if dns64Eligible(req, answer) && dns64Active {
			if stale == nil {
				stale = answer
			}
			return nil, stale, false, false, true
		}
		setCachedAnswerTTL(answer, now, cachedValue.Expire)
		return answer, stale, true, false, false
	}
	if stale == nil {
		stale = answer
	}
	return nil, stale, false, false, false
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
		if !listenerConfig.AllowWanClients && isWanClient(w.RemoteAddr()) && !isIPv6LoopbackListener(w.LocalAddr()) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "query refused, listener does not allow WAN clients: %s", w.RemoteAddr().String())
			answer := new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)
			_ = w.WriteMsg(answer)
			return
		}
		go p.detectLoop(m)
		q := m.Question[0]
		domain := canonicalName(q.Name)
		switch {
		case domain == "":
			answer := new(dns.Msg)
			answer.SetRcode(m, dns.RcodeFormatError)
			_ = w.WriteMsg(answer)
			return
		case domain == selfCheckInternalTestDomain:
			answer := resolveInternalDomainTestQuery(ctx, domain, m)
			_ = w.WriteMsg(answer)
			return
		}

		// Interception probe: if we're expecting a probe query and this matches,
		// signal the prober and respond NXDOMAIN. Used by both macOS pf probes
		// (_pf-probe-*) and Windows NRPT probes (_nrpt-probe-*) to verify that
		// DNS interception is actually routing queries to ctrld's listener.
		if p.signalInterceptProbe(domain) {
			answer := new(dns.Msg)
			answer.SetRcode(m, dns.RcodeNameError) // NXDOMAIN
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
		// The grade of the window must not depend on the goroutine below.
		p.health.countQuery()
		go func() {
			p.WithLabelValuesInc(statsQueriesCount, labelValues...)
			p.WithLabelValuesInc(statsClientQueriesCount, []string{ci.IP, ci.Mac, ci.Hostname}...)
			p.forceFetchingAPI(domain)
		}()
		if err := w.WriteMsg(answer); err != nil {
			ctrld.Log(ctx, p.querySampler.event(sampleClassSendResponseFailed, "").Err(err), "serveDNS: failed to send DNS response to client")
		}
	})

	g, ctx := errgroup.WithContext(context.Background())
	for _, proto := range []string{"udp", "tcp"} {
		proto := proto
		if needLocalIPv6Listener(p.cfg.Service.InterceptMode) {
			g.Go(func() error {
				s, errCh := runDNSServer(net.JoinHostPort("::1", strconv.Itoa(listenerConfig.Port)), proto, handler)
				defer s.Shutdown()
				select {
				case <-p.stopCh:
				case <-p.runAbortCh:
				case <-ctx.Done():
				case err := <-errCh:
					// Local ipv6 listener should not terminate ctrld.
					// It's a workaround for a quirk on Windows.
					mainLog.Load().Warn().Err(err).Msg("local ipv6 listener failed")
				}
				return nil
			})
		}
		// When we spawn a listener on 127.0.0.1, also spawn listeners on the RFC1918 addresses of the machine
		// if explicitly set via setting rfc1918 flag, so ctrld could receive queries from LAN clients.
		if needRFC1918Listeners(listenerConfig) {
			g.Go(func() error {
				for _, addr := range ctrld.Rfc1918Addresses() {
					func() {
						listenAddr := net.JoinHostPort(addr, strconv.Itoa(listenerConfig.Port))
						s, errCh := runDNSServer(listenAddr, proto, handler)
						defer s.Shutdown()
						select {
						case <-p.stopCh:
						case <-p.runAbortCh:
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

			select {
			case p.started <- struct{}{}:
			case <-p.stopCh:
				return nil
			case <-p.runAbortCh:
				return nil
			case <-ctx.Done():
				return nil
			}

			select {
			case <-p.stopCh:
			case <-p.runAbortCh:
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
	matchedRule := noRuleMatched
	matched := false
	zpaDNSEcho := false
	res = &upstreamForResult{srcAddr: addr.String()}

	defer func() {
		// Zscaler Private Access: under macOS Intercept Mode, pf routes Client
		// Connector's health-check query for zpaDNSEchoDomain into ctrld, which
		// answers it from the Control D upstream. Client Connector never sees the
		// answer on its own DNS path, so it keeps Private Access disabled.
		//
		// Route only that one exact name the way a Control D "bypass" rule does:
		// an empty upstream list, which proxy() resolves through upstream.os —
		// the system resolver set, which under Intercept Mode still includes
		// Client Connector's own DNS servers. Matching on the name alone covers
		// every record type, the same as a bypass rule.
		//
		// This runs after policy evaluation, and never touches `matched`. That
		// flag is also the source authorization bit: serveDNS refuses a query on
		// a Restricted listener when it is false, so forcing it true here would
		// let an unauthorized client resolve this name through such a listener.
		//
		// The scope is one fixed public health-check name: every other domain,
		// including all Private Access application domains, stays intercepted and
		// filtered by Control D. --intercept-mode hard opts out, the same as it
		// opts out of VPN DNS split routing.
		if zpaDNSEchoBypassActive() && canonicalName(domain) == zpaDNSEchoDomain {
			switch {
			case matchedRule == noRuleMatched:
				// The listener policy says nothing about this name, so the
				// built-in route decides. Network- and MAC-policy targets route
				// every name from a source and so state nothing about this one:
				// override them, and the default upstream, and label the result
				// so logs name the reason.
				upstreams = nil
				matchedPolicy = zpaDNSEchoPolicyName
				matchedRule = zpaDNSEchoDomain
				zpaDNSEcho = true
			case len(upstreams) == 0:
				// An explicit domain rule already selects the OS path: a rule
				// with empty targets, which is how a Control D profile's bypass
				// list reaches us (see the cfg.Listener rules built from
				// resolverConfig.Exclude). That is the documented pre-fix
				// workaround for this very bug, so keep the operator's own
				// labels but still classify it as the health check — otherwise
				// anyone who keeps the workaround after upgrading would route
				// correctly and then have the answer served from our cache,
				// losing the reconnect fix.
				zpaDNSEcho = true
			default:
				// Any other explicit domain rule is a deliberate non-OS route
				// for this exact name. That is operator intent, and the
				// supported way to opt out without leaving Intercept Mode, so
				// leave the policy's decision untouched.
			}
		}
		res.upstreams = upstreams
		res.matched = matched
		res.matchedPolicy = matchedPolicy
		res.matchedNetwork = matchedNetwork
		res.matchedRule = matchedRule
		res.zpaDNSEcho = zpaDNSEcho
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
	// DNS intercept recovery bypass: forward all queries to OS/DHCP resolver.
	// This runs when upstreams are unreachable (e.g., captive portal network)
	// and allows the network's DNS to handle authentication pages.
	//
	// An Internal Domain with explicit resolvers does not take part. The bypass
	// exists because general DNS is broken, which says nothing about the
	// administrator's own resolvers: they may well be reachable, and they are
	// to be tried first. Such a query continues to the normal flow, where it
	// reaches its configured resolvers first. In "explicit resolver only" mode
	// it fails if none answer; otherwise it falls back to the VPN resolvers and
	// the network's LAN nameservers, never to the public nameservers the bypass
	// may use.
	if dnsIntercept && p.recoveryBypass.Load() && !p.internalDomainExplicitUpstreams(req.ufr.upstreams) {
		ctrld.Log(ctx, mainLog.Load().Debug(), "Recovery bypass active: forwarding to OS resolver")
		resolver, err := ctrld.NewResolver(osUpstreamConfig)
		if err == nil {
			resolveCtx, cancel := osUpstreamConfig.Context(ctx)
			defer cancel()
			answer, _ := resolver.Resolve(resolveCtx, req.msg)
			if answer != nil {
				return &proxyResponse{answer: answer}
			}
		}
		ctrld.Log(ctx, mainLog.Load().Debug(), "OS resolver failed during recovery bypass")
		// Fall through to normal flow as last resort
	}

	var staleAnswer *dns.Msg
	upstreams := req.ufr.upstreams
	serveStaleCache := p.cache != nil && p.cfg.Service.CacheServeStale
	upstreamConfigs := p.upstreamConfigsFromUpstreamNumbers(upstreams)

	// Inverse queries must not be cached:
	// https://www.rfc-editor.org/rfc/rfc1035#section-7.4
	//
	// Neither must the Zscaler health check. Its whole purpose is to be observed
	// arriving on Client Connector's own DNS path, so it has to reach the OS
	// resolver on every poll — a locally served answer looks like a successful
	// lookup to us and like silence to Client Connector. This matters most on
	// reconnect: an answer cached while ZPA was disconnected would otherwise
	// outlive InitializeOsResolver() and keep Private Access disabled until the
	// entry's TTL (or Service.CacheTTLOverride) expired.
	cacheable := p.cache != nil && req.msg.Question[0].Qtype != dns.TypePTR && !req.ufr.zpaDNSEcho
	if req.ufr.zpaDNSEcho {
		serveStaleCache = false
	}

	if len(upstreamConfigs) == 0 {
		upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
		upstreams = []string{upstreamOS}
		// For OS resolver, local addresses are ignored to prevent possible looping.
		// However, on Active Directory Domain Controller, where it has local DNS server
		// running and listening on local addresses, these local addresses must be used
		// as nameservers, so queries for ADDC could be resolved as expected.
		if p.isAdDomainQuery(req.msg) && p.hasLocalDNS {
			ctrld.Log(ctx, mainLog.Load().Debug(),
				"AD domain query detected for %s in domain %s, using local DNS server",
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
		ctrld.Log(ctx, mainLog.Load().Debug(), "%s, %s, %s -> %v", req.ufr.matchedPolicy, req.ufr.matchedNetwork, req.ufr.matchedRule, upstreams)
	} else {
		switch {
		case req.ufr.zpaDNSEcho:
			// Reached when no policy matched the source, so the branch above did
			// not log the bypass. Named explicitly rather than falling into the
			// "no explicit policy matched" default.
			ctrld.Log(ctx, mainLog.Load().Debug(), "%s, %s -> %v", req.ufr.matchedPolicy, req.ufr.matchedRule, upstreams)
		case isSrvLanLookup(req.msg):
			upstreams = []string{upstreamOS}
			upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
			ctx = ctrld.LanQueryCtx(ctx)
			ctrld.Log(ctx, mainLog.Load().Debug(), "SRV record lookup, using upstreams: %v", upstreams)
		case isPrivatePtrLookup(req.msg):
			isLanOrPtrQuery = true
			if answer := p.proxyPrivatePtrLookup(ctx, req.msg); answer != nil {
				res.answer = answer
				res.clientInfo = true
				return res
			}
			upstreams, upstreamConfigs = p.upstreamsAndUpstreamConfigForPtr(upstreams, upstreamConfigs)
			ctx = ctrld.LanQueryCtx(ctx)
			ctrld.Log(ctx, mainLog.Load().Debug(), "private PTR lookup, using upstreams: %v", upstreams)
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
			ctrld.Log(ctx, mainLog.Load().Debug(), "lan hostname lookup, using upstreams: %v", upstreams)
		default:
			ctrld.Log(ctx, mainLog.Load().Debug(), "no explicit policy matched, using default routing -> %v", upstreams)
		}
	}

	if cacheable {
		dns64Prefix, dns64Active := netip.Prefix{}, false
		if req.msg.Question[0].Qtype == dns.TypeAAAA {
			dns64Prefix, dns64Active = p.activeDNS64Prefix()
		}
		for _, upstream := range upstreams {
			answer, stale, hit, dns64Hit, dns64Bypass := p.cachedResponse(req.msg, upstream, dns64Prefix, dns64Active, time.Now())
			if stale != nil {
				staleAnswer = stale
			}
			if dns64Bypass {
				ctrld.Log(ctx, mainLog.Load().Debug(), "dns64: bypassing cached empty-AAAA answer for synthesis")
			}
			if !hit {
				continue
			}
			if dns64Hit {
				ctrld.Log(ctx, mainLog.Load().Debug(), "dns64: hit cached response variant")
			} else {
				ctrld.Log(ctx, mainLog.Load().Debug(), "hit cached response")
			}
			p.health.countCacheHit()
			res.answer = answer
			res.cached = true
			return res
		}
	}

	// VPN DNS split routing (only in dns-intercept mode).
	//
	// An Internal Domain with explicit resolvers is skipped here: the
	// administrator named the resolvers for that suffix, and VPN suffixes
	// are auto-detected, so handing the query to a VPN DNS server first would
	// override an explicit selection with a discovered one. In fallback mode
	// the VPN DNS servers are asked later, once the configured resolvers have
	// not resolved the name.
	//
	// Internal Domains in OS-resolver mode are not skipped, they ask for the
	// endpoint's default resolution, which under intercept mode includes
	// the VPN's own resolver.
	if dnsIntercept && p.vpnDNS != nil && len(req.msg.Question) > 0 && !p.internalDomainExplicitUpstreams(upstreams) {
		domain := req.msg.Question[0].Name
		if vpnServers := p.vpnDNS.UpstreamForDomain(domain); len(vpnServers) > 0 {
			ctrld.Log(ctx, mainLog.Load().Debug(), "VPN DNS route matched for domain %s, using servers: %v", domain, vpnServers)

			var gotTransportFailure bool
			for _, server := range vpnServers {
				upstreamConfig := p.vpnDNS.upstreamConfigFor(server)
				ctrld.Log(ctx, mainLog.Load().Debug(), "Querying VPN DNS server: %s", server)

				dnsResolver, err := ctrld.NewResolver(upstreamConfig)
				if err != nil {
					ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to create VPN DNS resolver")
					continue
				}
				resolveCtx, cancel := upstreamConfig.Context(ctx)
				answer, err := dnsResolver.Resolve(resolveCtx, req.msg)
				cancel()
				if answer != nil {
					p.vpnDNS.VPNDNSReachable()
					ctrld.Log(ctx, mainLog.Load().Debug(), "VPN DNS query successful")
					if cacheable {
						ttl := 60 * time.Second
						if len(answer.Answer) > 0 {
							ttl = time.Duration(answer.Answer[0].Header().Ttl) * time.Second
						}
						for _, upstream := range upstreams {
							p.cache.Add(dnscache.NewKey(req.msg, upstream), dnscache.NewValue(answer, time.Now().Add(ttl)))
						}
					}
					return &proxyResponse{answer: answer}
				}
				gotTransportFailure = true
				ctrld.Log(ctx, mainLog.Load().Debug().Err(err), "VPN DNS server %s failed", server)
			}

			// Explicit VPN DNS routes are authoritative for their suffix. If all
			// routed servers fail at the transport layer while Windows is serving
			// retained VPN DNS state, fail closed instead of leaking VPN/internal
			// names to normal upstreams.
			if gotTransportFailure && p.vpnDNS.ShouldFailClosedAfterVPNDNSTransportFailure(domain, vpnServers) {
				ctrld.Log(ctx, mainLog.Load().Debug(),
					"All VPN DNS servers had transport failures for %s; returning SERVFAIL while retained VPN DNS state is active", domain)
				p.countFailedClientQuery(upstreams)
				answer := new(dns.Msg)
				answer.SetRcode(req.msg, dns.RcodeServerFailure)
				return &proxyResponse{answer: answer}
			}

			ctrld.Log(ctx, mainLog.Load().Debug(), "All VPN DNS servers failed, falling back to normal upstreams")
		}
	}

	// Domain-less VPN DNS fallback: when a query is going to upstream.os via a
	// split-rule (matched policy) and we have VPN DNS servers with no associated
	// domains, try those servers for this query. This handles cases like F5 VPN
	// where the VPN doesn't advertise DNS search domains but its DNS servers
	// know the internal zones referenced by split-rules (e.g., *.provisur.local).
	// These servers are NOT used for general OS resolver queries to avoid
	// polluting captive portal / DHCP flows.
	if dnsIntercept && p.vpnDNS != nil && req.ufr.matched &&
		len(upstreams) > 0 && upstreams[0] == upstreamOS &&
		len(req.msg.Question) > 0 {
		if dlServers := p.vpnDNS.DomainlessServers(); len(dlServers) > 0 {
			domain := req.msg.Question[0].Name
			ctrld.Log(ctx, mainLog.Load().Debug(),
				"Split-rule query %s going to upstream.os, trying %d domain-less VPN DNS servers first: %v",
				domain, len(dlServers), dlServers)

			var gotDNSAnswer bool
			var gotTransportFailure bool
			for _, server := range dlServers {
				upstreamCfg := p.vpnDNS.upstreamConfigFor(server)
				ctrld.Log(ctx, mainLog.Load().Debug(), "Querying domain-less VPN DNS server: %s", server)

				dnsResolver, err := ctrld.NewResolver(upstreamCfg)
				if err != nil {
					ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to create domain-less VPN DNS resolver")
					continue
				}
				resolveCtx, cancel := upstreamCfg.Context(ctx)
				answer, err := dnsResolver.Resolve(resolveCtx, req.msg)
				cancel()
				if answer != nil {
					gotDNSAnswer = true
					p.vpnDNS.VPNDNSReachable()
				}
				if answer != nil && answer.Rcode == dns.RcodeSuccess {
					ctrld.Log(ctx, mainLog.Load().Debug(),
						"Domain-less VPN DNS server %s answered %s successfully", server, domain)
					return &proxyResponse{answer: answer}
				}
				if answer != nil {
					ctrld.Log(ctx, mainLog.Load().Debug(),
						"Domain-less VPN DNS server %s returned %s for %s, trying next",
						server, dns.RcodeToString[answer.Rcode], domain)
				} else {
					gotTransportFailure = true
					ctrld.Log(ctx, mainLog.Load().Debug().Err(err),
						"Domain-less VPN DNS server %s failed for %s", server, domain)
				}
			}

			// If every domainless VPN DNS attempt failed before receiving a DNS
			// packet while Windows is serving retained VPN DNS state, fail closed
			// instead of asking LAN/public DNS about internal split-rule names and
			// caching false negatives. Reachable negative DNS responses still fall
			// through to the old OS fallback behavior below.
			if !gotDNSAnswer && gotTransportFailure && p.vpnDNS.ShouldFailClosedAfterVPNDNSTransportFailure(domain, dlServers) {
				ctrld.Log(ctx, mainLog.Load().Debug(),
					"All domain-less VPN DNS servers had transport failures for %s; returning SERVFAIL while retained VPN DNS state is active", domain)
				p.countFailedClientQuery(upstreams)
				answer := new(dns.Msg)
				answer.SetRcode(req.msg, dns.RcodeServerFailure)
				return &proxyResponse{answer: answer}
			}

			ctrld.Log(ctx, mainLog.Load().Debug(),
				"All domain-less VPN DNS servers failed for %s, falling back to OS resolver", domain)
		}
	}

	resolve1 := func(upstream string, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) (*dns.Msg, error) {
		ctrld.Log(ctx, mainLog.Load().Debug(), "sending query to %s: %s", upstream, upstreamConfig.Name)
		dnsResolver, err := ctrld.NewResolver(upstreamConfig)
		if err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to create resolver")
			return nil, err
		}
		resolveCtx, cancel := upstreamConfig.Context(ctx)
		defer cancel()
		return dnsResolver.Resolve(resolveCtx, msg)
	}
	resolve := func(upstream string, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) *dns.Msg {
		if upstreamConfig.UpstreamSendClientInfo() && req.ci != nil {
			ctrld.Log(ctx, mainLog.Load().Debug(), "including client info with the request")
			ctx = context.WithValue(ctx, ctrld.ClientInfoCtxKey{}, req.ci)
		}
		answer, err := resolve1(upstream, upstreamConfig, msg)

		// reset is not used here, because it also stops the failure count for
		// one second, and the failures already in flight must still count.
		if answer != nil {
			p.um.noteSuccess(upstream)
			return answer
		}

		// A failing minute must not push the state events out of the retained log.
		// A transport error names the endpoint it failed to reach, which for a
		// generated Internal Domain upstream is the organization's private
		// resolver address. Report the classification through the sampler and
		// keep the address-bearing error at debug.
		if isGeneratedInternalDomainUpstream(upstreamConfig) {
			ctrld.Log(ctx, mainLog.Load().Debug().Err(err), "failed to resolve query")
			ctrld.Log(ctx, p.querySampler.event(sampleClassInternalDomain, upstream).Str("failure", internalDomainFailureReason(err)),
				"failed to resolve query using an Internal Domain resolver")
		} else {
			ctrld.Log(ctx, p.querySampler.event(sampleClassResolveFailed, upstream).Err(err), "failed to resolve query")
		}

		// increase failure count when there is no answer
		// rehardless of what kind of error we get
		p.um.increaseFailureCount(upstream)

		if err != nil {
			// For timeout error (i.e: context deadline exceed), force re-bootstrapping.
			var e net.Error
			if errors.As(err, &e) && e.Timeout() {
				upstreamConfig.ReBootstrap()
			}
			// For network error, turn ipv6 off if enabled.
			if ctrld.HasIPv6() && (errUrlNetworkError(err) || errNetworkError(err)) {
				ctrld.DisableIPv6()
			}
		}

		return nil
	}
	// An Internal Domain in explicit-with-network-fallback mode moves on from a
	// configured resolver that answers SERVFAIL or NXDOMAIN, as it does from
	// one that does not answer. internalNegative keeps the best of those
	// answers, so a name nobody resolves gets a real negative answer.
	internalFallback := p.internalDomainFallbackUpstreams(upstreams)
	var internalNegative *dns.Msg
	for n, upstreamConfig := range upstreamConfigs {
		if upstreamConfig == nil {
			continue
		}
		logger := mainLog.Load().Debug().
			Str("upstream", upstreamConfig.String()).
			Str("query", req.msg.Question[0].Name).
			Bool("is_ad_query", p.isAdDomainQuery(req.msg)).
			Bool("is_lan_query", isLanOrPtrQuery)

		if p.isLoop(upstreamConfig) {
			ctrld.Log(ctx, logger, "DNS loop detected")
			continue
		}
		// A fallback-mode Internal Domain resolver that the monitor reports as
		// down is not waited on: off the organization network every query
		// would otherwise pay its timeout before the network fallback runs.
		// Nothing else marks a generated resolver up again, so skipping it
		// starts a background re-check that does.
		if internalFallback && p.um.isDown(upstreams[n]) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain resolver %s is down, skipping it", upstreams[n])
			p.internalDomainProbes.probe(p.um, upstreams[n], upstreamConfig, req.msg)
			continue
		}
		answer := resolve(upstreams[n], upstreamConfig, req.msg)
		if answer == nil {
			if serveStaleCache && staleAnswer != nil {
				ctrld.Log(ctx, mainLog.Load().Debug(), "serving stale cached response")
				p.health.countCacheHit()
				now := time.Now()
				setCachedAnswerTTL(staleAnswer, now, now.Add(staleTTL))
				res.answer = staleAnswer
				res.cached = true
				return res
			}
			continue
		}
		// Reject an answer whose question does not match the request before it
		// can be served or cached. A mismatched question means the upstream
		// answered a different name/type than asked; caching it would poison
		// the shared cache with wrong-domain records for the requested name.
		// See github.com/Control-D-Inc/ctrld/issues/322.
		if !sameQuestion(req.msg, answer) {
			ctrld.Log(ctx, mainLog.Load().Debug(),
				"discarding answer from %s: question mismatch (asked %q, got %q)",
				upstreams[n], questionString(req.msg), questionString(answer))
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
		if internalFallback && internalDomainFallbackRcode(answer.Rcode) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain resolver %s answered %s, trying next resolver",
				upstreams[n], dns.RcodeToString[answer.Rcode])
			internalNegative = betterInternalDomainNegative(internalNegative, answer)
			continue
		}

		// set compression, as it is not set by default when unpacking
		answer.Compress = true

		if cacheable {
			p.addCachedResponse(dnscache.NewKey(req.msg, upstreams[n]), answer)
			ctrld.Log(ctx, mainLog.Load().Debug(), "add cached response")
		}
		hostname := ""
		if req.ci != nil {
			hostname = req.ci.Hostname
		}
		// DNS64 synthesis for IPv6-only networks without CLAT: applied to the
		// policy-approved answer only, using the same upstream for the companion
		// A resolution. No-op unless the network state requires it.
		var synthesizedPrefix netip.Prefix
		answer, synthesizedPrefix = p.maybeDNS64(ctx, req.msg, answer, func(aReq *dns.Msg) *dns.Msg {
			key := dnscache.NewKey(aReq, upstreams[n])
			if cacheable {
				if cachedValue := p.cache.Get(key); cachedValue != nil {
					now := time.Now()
					if cachedValue.Expire.After(now) {
						cached := cachedValue.Msg.Copy()
						ctrld.SetCacheReply(cached, aReq, cached.Rcode)
						setCachedAnswerTTL(cached, now, cachedValue.Expire)
						return cached
					}
				}
			}
			resolved := resolve(upstreams[n], upstreamConfig, aReq)
			if cacheable && resolved != nil && sameQuestion(aReq, resolved) {
				p.addCachedResponse(key, resolved)
			}
			return resolved
		})
		if cacheable && synthesizedPrefix.IsValid() {
			p.addCachedResponse(dns64CacheKey(req.msg, upstreams[n], synthesizedPrefix), answer)
			ctrld.Log(ctx, mainLog.Load().Debug(), "dns64: add cached response variant")
		}
		ctrld.Log(ctx, mainLog.Load().Info(), "REPLY: %s -> %s (%s): %s", upstreams[n], req.ufr.srcAddr, hostname, dns.RcodeToString[answer.Rcode])
		res.answer = answer
		res.upstream = upstreamConfig.Endpoint
		return res
	}
	if internalFallback {
		ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain resolvers did not resolve the query; trying network resolvers")
		answer, negative := p.resolveInternalDomainOnNetwork(ctx, req.msg)
		if answer != nil {
			answer.Compress = true
			if cacheable {
				p.addCachedResponse(dnscache.NewKey(req.msg, upstreams[0]), answer)
				ctrld.Log(ctx, mainLog.Load().Debug(), "add cached response")
			}
			hostname := ""
			if req.ci != nil {
				hostname = req.ci.Hostname
			}
			ctrld.Log(ctx, mainLog.Load().Info(), "REPLY: internal domain network fallback -> %s (%s): %s", req.ufr.srcAddr, hostname, dns.RcodeToString[answer.Rcode])
			res.answer = answer
			return res
		}
		if negative = betterInternalDomainNegative(internalNegative, negative); negative != nil {
			ctrld.Log(ctx, mainLog.Load().Debug(), "no resolver resolved the internal domain; returning %s", dns.RcodeToString[negative.Rcode])
			negative.Compress = true
			res.answer = negative
			return res
		}
	}
	ctrld.Log(ctx, p.querySampler.event(sampleClassAllEndpointsFailed, ""), "all %v endpoints failed", journalUpstreamNames(upstreams))

	// An Internal Domain with explicit resolvers never takes the OS-resolver
	// catch-all below: it can reach public nameservers, ctrld's own fallback
	// included, which no mode selects for a private name. Fallback mode has
	// already tried the VPN resolvers and the network's LAN nameservers above.
	// The recovery flow exists for the loss of general DNS, not for one
	// unavailable internal server, so it is not started either.
	if p.internalDomainExplicitUpstreams(upstreams) {
		ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain resolvers unreachable; not using the OS resolver catch all")
	} else if p.leakOnUpstreamFailure() {
		if p.um.countHealthy(upstreams) == 0 {
			p.recoveryCancelMu.Lock()
			if p.recoveryCancel == nil {
				var reason RecoveryReason
				if upstreams[0] == upstreamOS {
					reason = RecoveryReasonOSFailure

				} else {
					reason = RecoveryReasonRegularFailure
				}
				mainLog.Load().Debug().Msgf("Selected upstreams unavailable; requesting recovery with reason: %v", reason)
				go queryRecoveryFn(p, reason)
			} else {
				mainLog.Load().Debug().Msg("Recovery already in progress; skipping duplicate trigger from down detection")
			}
			p.recoveryCancelMu.Unlock()
		} else {
			mainLog.Load().Debug().Msg("One upstream is down but at least one is healthy; skipping recovery trigger")
		}

		// attempt query to OS resolver while as a retry catch all
		// we dont want this to happen if leakOnUpstreamFailure is false
		if upstreams[0] != upstreamOS {
			ctrld.Log(ctx, mainLog.Load().Debug(), "attempting query to OS resolver as a retry catch all")
			answer := resolve(upstreamOS, osUpstreamConfig, req.msg)
			if answer != nil {
				ctrld.Log(ctx, mainLog.Load().Debug(), "OS resolver retry query successful")
				res.answer = answer
				res.upstream = osUpstreamConfig.Endpoint
				return res
			}
			ctrld.Log(ctx, mainLog.Load().Debug(), "OS resolver retry query failed")
		}
	}

	p.countFailedClientQuery(upstreams)
	answer := new(dns.Msg)
	answer.SetRcode(req.msg, dns.RcodeServerFailure)
	res.answer = answer
	return res
}

// countFailedClientQuery grades one client query that ended without an answer.
// A query that only Internal Domain resolvers serve stays out of the grade: an
// endpoint away from the organization network never reaches them, and that is
// not an outage of the query path.
func (p *prog) countFailedClientQuery(upstreams []string) {
	if p.internalDomainExplicitUpstreams(upstreams) {
		return
	}
	p.health.countFailedQuery()
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

// sameQuestion reports whether the upstream answer echoes the request's
// question. A well-behaved resolver always copies the question section from
// the query (RFC 1035 section 4.1.2); names are compared case-insensitively
// because DNS names are case-insensitive. A mismatch means the upstream
// answered a different name/type than asked - malformed or malicious - and the
// answer must not be served or cached, or it would poison the shared cache with
// wrong-domain records. See github.com/Control-D-Inc/ctrld/issues/322.
func sameQuestion(req, answer *dns.Msg) bool {
	if req == nil || answer == nil {
		return false
	}
	if len(req.Question) == 0 || len(answer.Question) == 0 {
		return false
	}
	rq, aq := req.Question[0], answer.Question[0]
	return rq.Qtype == aq.Qtype && rq.Qclass == aq.Qclass && strings.EqualFold(rq.Name, aq.Name)
}

// questionString renders a message's first question as "name/type" for logging.
func questionString(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "<none>"
	}
	q := msg.Question[0]
	return q.Name + "/" + dns.TypeToString[q.Qtype]
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

func needLocalIPv6Listener(interceptMode string) bool {
	if !ctrldnet.SupportsIPv6ListenLocal() {
		mainLog.Load().Debug().Msg("IPv6 listener: not needed — SupportsIPv6ListenLocal() is false")
		return false
	}
	// On Windows, there's no easy way for disabling/removing IPv6 DNS resolver, so we check whether we can
	// listen on ::1, then spawn a listener for receiving DNS requests.
	if runtime.GOOS == "windows" {
		mainLog.Load().Debug().Msg("IPv6 listener: enabled (Windows)")
		return true
	}
	// macOS: IPv6 DNS is blocked at the pf level (not intercepted). The [::1] listener
	// is not needed — macOS falls back to IPv4 DNS automatically. See #507 and
	// docs/pf-dns-intercept.md for why IPv6 interception on macOS is not feasible
	// (sendmsg EINVAL from ::1 to global unicast, nat-on-lo0 doesn't fire for route-to).
	if runtime.GOOS == "darwin" {
		mainLog.Load().Debug().Msg("IPv6 listener: not needed (macOS — IPv6 DNS blocked at pf, fallback to IPv4)")
		return false
	}
	mainLog.Load().Debug().Str("os", runtime.GOOS).Str("interceptMode", interceptMode).Msg("IPv6 listener: not needed")
	return false
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

	errCh := make(chan error, 1)
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

	if ci.IP == "" {
		mainLog.Load().Debug().Msgf("client info entry with empty IP address: %v", ci)
	} else {
		ci.Self = p.queryFromSelf(ci.IP)
	}

	// In DNS intercept mode, ALL queries are from the local machine — pf/WFP
	// intercepts outbound DNS and redirects to ctrld. The source IP may be a
	// virtual interface (Tailscale, VPN) that has no ARP/MAC entry, causing
	// missing x-cd-mac, x-cd-host, and x-cd-os headers. Force Self=true and
	// populate from the primary physical interface info.
	if dnsIntercept && !ci.Self {
		ci.Self = true
	}

	// If this is a query from self, but ci.IP is not loopback IP,
	// try using hostname mapping for lookback IP if presents.
	if ci.Self {
		if name := p.ciTable.LocalHostname(); name != "" {
			ci.Hostname = name
		}
		// If MAC is still empty (e.g., query arrived via virtual interface IP
		// like Tailscale), fall back to the loopback MAC mapping which addSelf()
		// populates from the primary physical interface.
		if ci.Mac == "" {
			if mac := p.ciTable.LookupMac("127.0.0.1"); mac != "" {
				ci.Mac = mac
			}
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

		req := &controld.ResolverConfigRequest{
			RawUID:   cdUID,
			Version:  rootCmd.Version,
			Metadata: ctrld.SystemMetadataRuntime(context.Background()),
		}
		_, err := controld.FetchResolverConfig(context.Background(), req, cdDev)
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
	if !p.beginNetworkActivity() {
		return
	}
	defer p.netMonitorWG.Done()
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
		if !p.beginNetworkActivity() {
			return nil, nil
		}
		defer p.netMonitorWG.Done()
		shutdown := p.networkActivityDone()
		select {
		case <-shutdown:
			return nil, nil
		case p.apiForceReloadCh <- struct{}{}:
		case <-p.stopCh:
			return nil, nil
		case <-p.runAbortCh:
			return nil, nil
		}
		// Wait here to prevent abusing API if we are flooded.
		p.mu.Lock()
		wait := timeDurationOrDefault(p.cfg.Service.ForceRefetchWaitTime, 30) * time.Second
		p.mu.Unlock()
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-shutdown:
		case <-p.stopCh:
		case <-p.runAbortCh:
		}
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
	netIP, err := netip.ParseAddr(ip)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msgf("could not parse IP: %q", ip)
		return false
	}

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

// needRFC1918Listeners reports whether ctrld need to spawn listener for RFC 1918 addresses.
// This is helpful for non-desktop platforms to receive queries from LAN clients.
func needRFC1918Listeners(lc *ctrld.ListenerConfig) bool {
	return rfc1918 && lc.IP == "127.0.0.1" && lc.Port == 53
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
				tsaddr.CGNATRange().Contains(addr) ||
				isServiceContinuityAddr(addr)
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

// ipv4ServiceContinuityPrefix is the RFC 7335 IPv4 Service Continuity Prefix
// (192.0.0.0/29), used by the CLAT in 464XLAT/DS-Lite transition setups. On such
// networks (common on IPv6-only cellular carriers and iPhone hotspots) the local
// machine's DNS queries reach ctrld with a source in this range (e.g. 192.0.0.2),
// so they must be treated as local, not WAN. Go's netip.IsPrivate does not cover
// this range — the same reason the CGNAT range is special-cased below. See #552.
var ipv4ServiceContinuityPrefix = netip.MustParsePrefix("192.0.0.0/29")

// isServiceContinuityAddr reports whether ip is in the RFC 7335 IPv4 Service
// Continuity Prefix (464XLAT/DS-Lite CLAT).
func isServiceContinuityAddr(ip netip.Addr) bool {
	return ipv4ServiceContinuityPrefix.Contains(ip)
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
		!tsaddr.CGNATRange().Contains(ip) &&
		!isServiceContinuityAddr(ip)
}

// isIPv6LoopbackListener reports whether the listener address is [::1].
// The [::1] listener only serves locally-redirected traffic (via pf on macOS
// or system DNS on Windows), so queries arriving on it are always from this
// machine — even when the source IP is a global IPv6 address (pf preserves the
// original source IP during rdr).
func isIPv6LoopbackListener(na net.Addr) bool {
	if ap, err := netip.ParseAddrPort(na.String()); err == nil {
		return ap.Addr() == netip.IPv6Loopback()
	}
	return false
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

// networkChangeCallback fences even callbacks already dispatched by netmon
// when Close begins. The monitor does not track those callback goroutines.
func (p *prog) networkChangeCallback(fn netmon.ChangeFunc) netmon.ChangeFunc {
	return func(delta *netmon.ChangeDelta) {
		if !p.beginNetworkActivity() {
			return
		}
		defer p.netMonitorWG.Done()
		fn(delta)
	}
}

// monitorNetworkChanges starts monitoring for network interface changes.
func (p *prog) monitorNetworkChanges() error {
	mon, err := newNetworkChangeMonitorFn(func(format string, args ...any) {
		// Always fetch the latest logger (and inject the prefix).
		mainLog.Load().Printf("netmon: "+format, args...)
	})
	if err != nil {
		return fmt.Errorf("creating network monitor: %w", err)
	}
	mon.RegisterChangeCallback(p.networkChangeCallback(func(delta *netmon.ChangeDelta) {
		p.handleNetworkChange(delta, mon.IsMajorChangeFrom(delta.Old, delta.New))
	}))
	if !p.setNetMonitor(mon) {
		_ = mon.Close()
		mainLog.Load().Debug().Msg("network monitor discarded, ctrld is stopping")
		return nil
	}
	mon.Start()
	mainLog.Load().Debug().Msg("Network monitor started")
	return nil
}

// handleNetworkChange is the network monitor callback, kept separate for synthetic deltas.
func (p *prog) handleNetworkChange(delta *netmon.ChangeDelta, isMajorChange bool) {
	// netmon v1.74.0 dispatches callbacks concurrently and caches only major
	// snapshots. Minor events refer to that cache through Old. The synthetic
	// delta.Major flag after a time jump does not change the cache.
	p.networkSourceMu.Lock()
	currentState := networkChangeCurrentStateFn(delta)
	current := networkSnapshotCurrent(delta, isMajorChange, currentState)
	if delta.TimeJumped {
		// A late callback still tells that the host woke, but the network of
		// the wake is the one that netmon holds now.
		wakeState := delta.New
		if !current {
			wakeState = currentState
		}
		p.noteHostWoke("netmon", 0, wakeState)
	}
	// Only a current callback becomes the baseline of the next diff. A late
	// callback that a newer snapshot replaced would hide the changes between
	// the callback before it and the callback after it.
	before := p.deltaBeforeState(delta, currentState, current, isMajorChange)
	changes := diffNetworkDelta(before, delta.New)
	if current && hasAddOrRemove(changes) {
		refreshInterfaceMeta()
	}
	// The noise test runs before any other work, because the point of the class
	// is that a storm starts no pfctl and no scutil process.
	if current && noiseDelta(before, delta.New, delta.TimeJumped, changes) {
		p.networkSourceMu.Unlock()
		p.noteNoiseDelta(changes)
		return
	}
	// A superseded snapshot never becomes a transition, so it takes no ID and
	// reports zero.
	var transitionID uint64
	changed := false
	changedInterface := ""
	sourceSnapshotAvailable := false
	before4, before6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	after4, after6 := before4, before6
	// The newer callback of this epoch carries the same interface changes, so
	// this outcome reports at debug and stays out of the journal.
	outcome := transitionOutcomeSnapshotSuperseded
	defer func() {
		stateBefore, stateAfter := networkStateOrEmpty(before), networkStateOrEmpty(delta.New)
		networkTransitionEvent(outcome).Uint64("transition_id", transitionID).
			Bool("is_major_change", isMajorChange).Bool("changed", changed).
			Str("interface", changedInterface).
			Strs("changed_interfaces", changedInterfaceNames(changes)).
			Bool("time_jumped", delta.TimeJumped).
			Str("default_route_before", stateBefore.DefaultRouteInterface).
			Str("default_route_after", stateAfter.DefaultRouteInterface).
			Bool("have_v4_before", stateBefore.HaveV4).Bool("have_v4_after", stateAfter.HaveV4).
			Bool("have_v6_before", stateBefore.HaveV6).Bool("have_v6_after", stateAfter.HaveV6).
			Str("source_ipv4_before", before4.String()).Str("source_ipv6_before", before6.String()).
			Str("source_ipv4_after", after4.String()).
			Str("source_ipv6_after", after6.String()).
			Bool("source_snapshot_available", sourceSnapshotAvailable).Str("outcome", outcome).
			Msg(networkTransitionMessage)
	}()
	if !current {
		p.networkSourceMu.Unlock()
		return
	}
	p.flushNoiseSummary()
	outcome = transitionOutcomeIgnored
	transitionID = p.networkTransitionGen.Add(1)
	sourceState := delta.New
	// A late major callback and reordered minor callbacks share one cache
	// epoch. For these cases, source validity comes from the OS, not ordering.
	if delta.Monitor != nil && (!isMajorChange || (p.networkSourceEpoch == currentState && p.networkSourceState != currentState)) {
		fresh, err := readNetworkSourceStateFn()
		if err != nil || fresh == nil {
			if !p.networkSourceReadFailed {
				mainLog.Load().Warn().Uint64("transition_id", transitionID).
					Msg("Network source snapshot unavailable; source writes deferred")
			}
			p.networkSourceReadFailed = true
			sourceState = nil
		} else {
			snapshot := *fresh
			snapshot.DefaultRouteInterface = currentState.DefaultRouteInterface
			sourceState = &snapshot
			if p.networkSourceReadFailed {
				mainLog.Load().Warn().Uint64("transition_id", transitionID).Msg("Network source snapshot available again")
			}
			p.networkSourceReadFailed = false
		}
	}
	p.networkSourceState, p.networkSourceEpoch = sourceState, currentState
	sourceSnapshotAvailable = sourceState != nil
	validateDefaultLocalIPsFromDelta(sourceState, transitionID)
	after4, after6 = ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	// The network of this callback belongs to the epoch that the lines above
	// store. A store after the unlock can overwrite the network of a newer
	// callback. The header render reads the hardware ports, so it runs after
	// the unlock and starts no process under the lock.
	p.lastNetworkState.Store(currentState)
	// HasIPv6 reads the flag that this callback stores, so one monitor serves
	// the whole process.
	ctrld.SetIPv6Available(currentState.HaveV6)
	p.networkSourceMu.Unlock()
	p.refreshLogHeader()
	describeInterfaceChanges(changes, interfaceMetaFor)
	logInterfaceChanges(transitionID, changes)

	p.handleDNS64NetworkChange(delta, isMajorChange)
	validIfaces := networkChangeValidInterfacesFn()

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
				// The new interface is the active one, or the change ends as
				// no_active_interface and nothing reconciles.
				activeInterfaceExists = true
				changed = true
				changeIPs = usableNewIPs
				changedInterface = ifaceName
				mainLog.Load().Debug().
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
				changedInterface = ifaceName
				mainLog.Load().Debug().
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
		mainLog.Load().Debug().Msgf("Default route changed from %s to %s", delta.Old.DefaultRouteInterface, delta.New.DefaultRouteInterface)
	}

	if !changed {
		mainLog.Load().Debug().Msg("Ignoring interface change - no valid interfaces affected")
		// Minor interface changes can still accompany pf/WFP or VPN DNS changes.
		// On macOS, bound the immediate full reconciliation so link-local-only
		// notification storms do not run pfctl/scutil work for every event.
		// Windows keeps the existing immediate behavior. Tunnel changes always
		// bypass the macOS limit, and delayed checks provide a trailing refresh.
		if dnsIntercept && p.dnsInterceptState != nil {
			networkChangeIgnoredInterceptFn(p, delta, time.Now())
		}
		return
	}

	if !activeInterfaceExists {
		outcome = "no_active_interface"
		mainLog.Load().Debug().Msg("No active interfaces found, skipping reinitialization")
		return
	}

	// An ignored event must not cancel this accepted transition. Only a newer
	// accepted transition can replace its source commit or debounced recovery.
	p.networkSourceMu.Lock()
	if p.networkAcceptedGen.Load() > transitionID {
		p.networkSourceMu.Unlock()
		outcome = "superseded"
		return
	}
	p.networkAcceptedGen.Store(transitionID)
	p.networkSourceMu.Unlock()

	mainLog.Load().Debug().Msg("Link state changed, re-bootstrapping")
	for _, uc := range p.cfg.Upstream {
		uc.ReBootstrap()
	}

	// Get IPs from default route interface in new state
	selfIP := networkChangeDefaultRouteIPFn()

	// Ensure that selfIP is an IPv4 address.
	// If defaultRouteIP mistakenly returns an IPv6 (such as a ULA), clear it
	if ip := net.ParseIP(selfIP); ip != nil && ip.To4() == nil {
		mainLog.Load().Debug().Msgf("defaultRouteIP returned a non-IPv4 address: %s, ignoring it", selfIP)
		selfIP = ""
	}
	// Route discovery can lag the delta; do not reintroduce an invalid source.
	if ip := net.ParseIP(selfIP); ip != nil && sourceInvalidReason(delta.New, ip) != "" {
		selfIP = ""
	}
	var ipv6 string

	if delta.New.DefaultRouteInterface != "" {
		mainLog.Load().Debug().Msgf("default route interface: %s, IPs: %v", delta.New.DefaultRouteInterface, delta.New.InterfaceIPs[delta.New.DefaultRouteInterface])
		for _, ip := range delta.New.InterfaceIPs[delta.New.DefaultRouteInterface] {
			if sourceInvalidReason(delta.New, net.ParseIP(ip.Addr().String())) != "" {
				continue
			}
			ipAddr, _ := netip.ParsePrefix(ip.String())
			addr := ipAddr.Addr()
			if selfIP == "" && addr.Is4() {
				mainLog.Load().Debug().Msgf("checking IP: %s", addr.String())
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
		mainLog.Load().Debug().Msgf("no default route interface found, using changed IPs: %v", changeIPs)
		for _, ip := range changeIPs {
			ipAddr, _ := netip.ParsePrefix(ip.String())
			addr := ipAddr.Addr()
			if selfIP == "" && addr.Is4() {
				mainLog.Load().Debug().Msgf("checking IP: %s", addr.String())
				if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
					selfIP = addr.String()
				}
			}
			if addr.Is6() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				ipv6 = addr.String()
			}
		}
	}

	// An ignored event can change source validity without replacing recovery.
	// Recheck addresses against the newest state after blocking route lookup.
	p.networkSourceMu.Lock()
	if p.networkAcceptedGen.Load() != transitionID {
		p.networkSourceMu.Unlock()
		outcome = "superseded"
		return
	}
	latestState := p.sourceCommitState(delta)
	sourceSnapshotAvailable = latestState != nil
	validateDefaultLocalIPsFromDelta(latestState, transitionID)
	// Only keep candidate addresses that still exist on an up interface.
	if ip := net.ParseIP(selfIP); ip != nil && ip.To4() != nil && latestState != nil && sourceInvalidReason(latestState, ip) == "" {
		ctrld.SetDefaultLocalIPv4(ip)
		if !isMobile() && p.ciTable != nil {
			p.ciTable.SetSelfIP(selfIP)
		}
	}
	if ip := net.ParseIP(ipv6); ip != nil && latestState != nil && sourceInvalidReason(latestState, ip) == "" {
		ctrld.SetDefaultLocalIPv6(ip)
	}
	after4, after6 = ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	p.networkSourceMu.Unlock()
	mainLog.Load().Debug().Msgf("Set default local IPv4: %s, IPv6: %s", selfIP, ipv6)

	outcome = "accepted"
	networkChangeReconcileFn(p, transitionID)
	p.logNetworkSnapshot("transition")
	if p.dnsConfig != nil {
		p.dnsConfig.noteActivity(networkEventsNowFn())
	}
}

// reconcileNetworkChange is the first DNS/PF mutation boundary after source updates.
func (p *prog) reconcileNetworkChange(transitionID uint64) {
	// we only trigger recovery flow for network changes on non router devices
	if router.Name() == "" {
		p.debounceRecovery(transitionID)
	}

	// After network changes, verify our pf anchor is still active and
	// refresh VPN DNS state. Order matters: tunnel checks first (may rebuild
	// anchor), then VPN DNS refresh (updates exemptions in anchor), then
	// delayed re-checks for async VPN teardown.
	if dnsIntercept && p.dnsInterceptState != nil {
		if !p.pfStabilizing.Load() {
			p.ensurePFAnchorActive()
		}
		// Check tunnel interfaces unconditionally — it decides internally
		// whether to enter stabilization or rebuild immediately.
		p.checkTunnelInterfaceChanges()
		// Refresh VPN DNS routes — runs after tunnel checks so the anchor
		// rebuild includes current VPN DNS exemptions.
		if p.vpnDNS != nil {
			p.vpnDNS.Refresh(true)
		}
		// Schedule delayed re-checks to catch async VPN teardown changes.
		p.scheduleDelayedRechecks()
	}
}

// handleDNSInterceptIgnoredNetworkChange runs the DNS-intercept work for a
// network delta that did not affect a usable interface. Keeping this path in a
// method lets tests exercise the callback wiring with synthetic deltas.
func (p *prog) handleDNSInterceptIgnoredNetworkChange(delta *netmon.ChangeDelta, now time.Time) {
	reconcileNow := false
	// Stabilization owns PF repair. Do not consume the next leading-edge slot
	// until an ignored delta can actually perform the corresponding PF check.
	if !p.pfStabilizing.Load() {
		reconcileNow = p.dnsInterceptIgnoredChangeReconcileDue(now)
		if reconcileNow {
			p.ensurePFAnchorActive()
		}
	}

	// Check tunnel interfaces unconditionally — it decides internally whether
	// to enter stabilization or rebuild immediately.
	tunnelChanged := p.checkTunnelInterfaceChanges()
	// Schedule delayed re-checks to catch async VPN teardown changes. These also
	// refresh the OS resolver and VPN DNS routes.
	p.scheduleDelayedRechecks()

	// Detect interface appearance/disappearance — hypervisors (Parallels,
	// VMware, VirtualBox) reload pf when creating/destroying virtual network
	// interfaces, which can corrupt pf's internal translation state. The rdr
	// rules survive in text form (watchdog says "intact") but stop evaluating.
	// Spawn an async monitor that probes pf interception with backoff and forces
	// a full pf reload if broken.
	if delta.Old != nil {
		changedAction := "removed"
		changedIface := interfaceOnlyIn(delta.Old.Interface, delta.New.Interface)
		if changedIface == "" {
			changedAction = "added"
			changedIface = interfaceOnlyIn(delta.New.Interface, delta.Old.Interface)
		}
		if changedIface != "" {
			journal(mainLog.Load().Info()).Str("interface", changedIface).
				Str("class", interfaceMetaFor(changedIface).Class).
				Str("action", changedAction).
				Msg("DNS intercept: interface appeared/disappeared — starting interception probe monitor")
			go p.pfInterceptMonitor()
		}
	}

	// Refresh VPN DNS immediately for real tunnel changes even when the periodic
	// ignored-change reconciliation is currently rate-limited - but not while
	// stabilization owns pf. A refresh rebuilds the anchor, and these deltas arrive
	// exactly when a VPN is bringing its own ruleset up, which is the collision
	// stabilization is there to prevent. checkTunnelInterfaceChanges keeps the
	// observation pending, so the transition is retried rather than dropped.
	if p.vpnDNS != nil && (reconcileNow || tunnelChanged) && !p.pfStabilizing.Load() {
		p.vpnDNS.Refresh(true)
	}
}

// interfaceOnlyIn names one interface that have holds and lack does not. The
// loopback stays out, because it never appears and never goes away.
func interfaceOnlyIn(have, lack map[string]netmon.Interface) string {
	for name := range have {
		if name == "lo0" {
			continue
		}
		if _, exists := lack[name]; !exists {
			return name
		}
	}
	return ""
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

var errOsHealthcheckSuppressed = errors.New("upstream os health check suppressed")

// upstreamFailureLog keeps one error line for each upstream of one recovery
// pass. The pass retries every two seconds until the upstream answers, and the
// first line already names the fault, so the failures that follow it go to
// debug.
type upstreamFailureLog struct{ reported bool }

// report logs one failed check of upstream.
func (l *upstreamFailureLog) report(upstream string, uc *ctrld.UpstreamConfig, err error, duration time.Duration) {
	level := mainLog.Load().Error
	if l.reported {
		level = mainLog.Load().Debug
	}
	l.reported = true
	logUpstreamProbeFailure(upstream, uc, err, level, "Upstream check failed after %v", duration)
}

// checkUpstreamOnce sends a test query to the specified upstream.
// Returns nil if the upstream responds successfully.
func (p *prog) checkUpstreamOnce(upstream string, uc *ctrld.UpstreamConfig, failures *upstreamFailureLog) error {
	mainLog.Load().Debug().Msgf("Starting check for upstream: %s", upstream)

	resolver, err := ctrld.NewResolver(uc)
	if err != nil {
		logUpstreamProbeFailure(upstream, uc, err, mainLog.Load().Error, "Failed to create resolver")
		return err
	}

	timeout := 1000 * time.Millisecond
	if uc.Timeout > 0 {
		timeout = time.Millisecond * time.Duration(uc.Timeout)
	}
	mainLog.Load().Debug().Msgf("Timeout for upstream %s: %s", upstream, timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	uc.ReBootstrap()
	mainLog.Load().Debug().Msgf("Rebootstrapping resolver for upstream: %s", upstream)

	start := time.Now()
	msg := uc.VerifyMsg()
	_, err = resolver.Resolve(ctx, msg)
	duration := time.Since(start)

	if err != nil {
		// Demote upstream.os check failures to debug while WFP loopback
		// protect is active: an external WFP block filter is interfering
		// with plain DNS so repeated failures here are expected. Other
		// upstreams keep error level so real outages stay visible.
		if upstream == upstreamOS && p.osHealthcheckSuppressed() {
			mainLog.Load().Debug().Err(err).Msgf("Upstream %s check failed after %v (WFP loopback protect active)", upstream, duration)
			return errOsHealthcheckSuppressed
		}
		// A no-route/network-unreachable failure means the endpoint's address
		// family is available locally but unroutable (e.g. an IPv6 DoH endpoint
		// while IPv6 is up but has no route). These repeat until the route
		// returns and are handled by bounded backoff in the recovery loop, so
		// keep them at debug to avoid sustained error-log spam.
		if ctrldnet.IsUnreachable(err) {
			mainLog.Load().Debug().Err(err).Msgf("Upstream %s check failed after %v (network unreachable)", upstream, duration)
			return err
		}
		failures.report(upstream, uc, err, duration)
		return err
	}
	mainLog.Load().Debug().Msgf("Upstream %s responded successfully in %v", upstream, duration)
	return nil
}

// recoveryDebounceWindow is the time to wait after the last network change
// before triggering handleRecovery. This coalesces rapid consecutive network
// changes (e.g., hotspot→LAN causing en1 drop + en0 pickup + en1 re-pickup)
// into a single recovery pass, avoiding the cancel-and-restart race that
// leaves DoH transports in a stale state.
const recoveryDebounceWindow = 500 * time.Millisecond

// recoveryResolverReason names this flow in the OS resolver events, so a
// reader tells a resolver read of the recovery from every other read.
const recoveryResolverReason = "recovery"

// debounceRecovery schedules a handleRecovery(NetworkChange) call after a debounce
// window. If called again before the window expires, the timer is reset so that
// recovery runs once with the final network state. All other state updates (IP,
// pf anchor, VPN DNS, tunnel checks) run immediately — only the recovery flow
// with its upstream probing and DHCP bypass logic is debounced.
func (p *prog) debounceRecovery(transitionID uint64) {
	p.networkSourceMu.Lock()
	defer p.networkSourceMu.Unlock()
	if p.networkAcceptedGen.Load() != transitionID {
		return
	}
	p.recoveryDebounceMu.Lock()
	defer p.recoveryDebounceMu.Unlock()
	if p.networkActivityClosed() {
		return
	}

	if p.recoveryDebounceTimer != nil {
		p.recoveryDebounceTimer.Stop()
		mainLog.Load().Debug().Msg("Recovery debounce: resetting timer (rapid network change)")
	}
	p.recoveryDebounceTimer = time.AfterFunc(recoveryDebounceWindow, func() {
		if !p.beginNetworkActivity() {
			return
		}
		defer p.netMonitorWG.Done()
		p.networkSourceMu.Lock()
		if p.networkAcceptedGen.Load() != transitionID {
			p.networkSourceMu.Unlock()
			return
		}
		p.recoveryDebounceMu.Lock()
		p.recoveryDebounceTimer = nil
		p.recoveryDebounceMu.Unlock()
		p.networkSourceMu.Unlock()
		handleRecoveryForTransitionFn(p, RecoveryReasonNetworkChange, transitionID)
	})
	mainLog.Load().Debug().Msg("Recovery debounce: scheduled (500ms window)")
}

// endRecovery closes one recovery pass. Support reads the end event and the
// snapshot that follows it to learn what the recovery left behind.
func (p *prog) endRecovery(diagnostic *recoveryDiagnostic, outcome, targetBefore string) {
	// A superseded pass changed nothing that it owns any more. Its successor
	// owns the loopback target and the bypass flag, so reading them here would
	// report the state of the successor.
	if outcome == recoveryOutcomeSuperseded {
		diagnostic.interceptTargetAction = interceptTargetActionUnchanged
		diagnostic.bypassActive = false
	} else {
		diagnostic.interceptTargetAction = interceptTargetAction(targetBefore, p.interceptTargetSnapshot())
		diagnostic.bypassActive = p.recoveryBypass.Load()
	}
	diagnostic.end(outcome)
	p.logNetworkSnapshot("recovery_end")
	// The resolver table of the host settles after the recovery, so the poll
	// stays fast until it does.
	if p.dnsConfig != nil {
		p.dnsConfig.noteActivity(networkEventsNowFn())
	}
}

// The actions that one recovery takes on the loopback DNS target.
const (
	interceptTargetActionUnchanged = "unchanged"
	interceptTargetActionRemoved   = "removed"
	interceptTargetActionSet       = "set"
)

// interceptTargetAction names what one recovery did to the loopback DNS
// target. The target value alone does not say whether this pass wrote it.
func interceptTargetAction(before, after string) string {
	switch {
	case before == after:
		return interceptTargetActionUnchanged
	case after == "":
		return interceptTargetActionRemoved
	default:
		return interceptTargetActionSet
	}
}

// handleRecovery performs a unified recovery by removing DNS settings,
// canceling existing recovery checks for network changes, but coalescing duplicate
// upstream failure recoveries, waiting for recovery to complete (using a cancellable context without timeout),
// and then re-applying the DNS settings.
func (p *prog) handleRecovery(reason RecoveryReason) {
	p.handleRecoveryForTransition(reason, 0)
}

func (p *prog) handleRecoveryForTransition(reason RecoveryReason, transitionID uint64) {
	if !p.beginNetworkActivity() {
		return
	}
	defer p.netMonitorWG.Done()
	p.networkSourceMu.Lock()
	if transitionID != 0 && p.networkAcceptedGen.Load() != transitionID {
		p.networkSourceMu.Unlock()
		mainLog.Load().Debug().Uint64("transition_id", transitionID).Msg("Recovery skipped: transition superseded")
		return
	}
	// Admission and completion use the same pool. A failed OS-only policy
	// is not evidence that configured general DNS is unavailable. Check here,
	// rather than only at the query, because a queued trigger can arrive late.
	upstreams := p.buildRecoveryUpstreams(reason)
	upstreamNames := make([]string, 0, len(upstreams))
	for name := range upstreams {
		upstreamNames = append(upstreamNames, name)
	}
	slices.Sort(upstreamNames)
	if reason == RecoveryReasonOSFailure {
		if _, osOnly := upstreams[upstreamOS]; !osOnly {
			for _, name := range upstreamNames {
				if !p.um.isDown(name) {
					p.networkSourceMu.Unlock()
					p.refreshOSResolverAfterRecoverySkip(name)
					return
				}
			}
		}
	}
	recoveryCtx, gen, interceptRecovery, ok := p.beginRecovery(reason)
	p.networkSourceMu.Unlock()
	if !ok {
		mainLog.Load().Debug().Uint64("transition_id", transitionID).
			Uint64("recovery_generation", p.recoveryGen.Load()).
			Msg("Upstream recovery already in progress; skipping duplicate trigger")
		return
	}
	diagnostic := recoveryDiagnostic{transitionID: transitionID, generation: gen, reason: reason, started: time.Now()}
	journal(diagnostic.event(mainLog.Load().Info())).Bool("intercept", interceptRecovery).
		Strs("probe_upstreams", journalUpstreamNames(upstreamNames)).Msg("Recovery begin")
	p.logNetworkSnapshot("recovery_begin")
	targetBefore := p.interceptTargetSnapshot()
	outcome := recoveryOutcomeSuperseded
	defer func() { p.endRecovery(&diagnostic, outcome, targetBefore) }()
	// Clean every exit, including shutdown before the first DNS mutation.
	// Run cleanup before the end snapshot so it reports the final state.
	defer p.recoveryCanceledCleanup(gen)
	if recoveryCtx.Err() != nil {
		if p.recoveryGen.Load() == gen {
			outcome = recoveryOutcomeCanceled
		}
		return
	}
	if reason == RecoveryReasonNetworkChange {
		mainLog.Load().Debug().Msg("Network change recovery now owns shared recovery state")
	}

	// For network changes, force-reset all upstream transports synchronously.
	// The lazy ReBootstrap() called earlier in the network change callback only
	// sets a flag — the old transport's dead connections can still be used by
	// recovery probes, causing context deadline timeouts. ForceReBootstrap()
	// closes old connections and creates fresh transports so probes succeed on
	// first attempt.
	if reason == RecoveryReasonNetworkChange {
		for _, uc := range p.cfg.Upstream {
			if uc != nil {
				uc.ForceReBootstrap()
			}
		}
		mainLog.Load().Info().Msg("Force-reset upstream transports for network change recovery")
	}

	// In DNS intercept mode, don't tear down WFP/pf filters.
	// Instead, enable recovery bypass so proxy() forwards queries to
	// the OS/DHCP resolver. This handles captive portal authentication
	// without the overhead of filter teardown/rebuild.
	if interceptRecovery {
		journal(mainLog.Load().Info()).Msg("DNS intercept recovery: enabling DHCP bypass (filters stay active)")

		// Reinitialize OS resolver to discover DHCP servers on the new network.
		mainLog.Load().Debug().Msg("DNS intercept recovery: discovering DHCP nameservers")
		// The effective list adds a synthetic public resolver when the network
		// gave none, so the journal reports the discovered list instead.
		resolverNameservers, systemNameservers := initializeOsResolverWithSystemNameserversFn(true, recoveryResolverReason)
		diagnostic.dhcpServers = systemNameservers
		if len(systemNameservers) == 0 {
			journal(mainLog.Load().Warn()).Msg("DNS intercept recovery: no DHCP nameservers found")
		} else {
			journal(mainLog.Load().Info()).Strs("dhcp_servers", systemNameservers).
				Msgf("DNS intercept recovery: found DHCP nameservers: %v", systemNameservers)
		}

		// If the new network provides no usable IPv4 DNS (e.g. IPv6-only
		// tethering with 464XLAT), macOS cannot emit DNS queries at all and
		// pf has nothing to intercept. Ensure a loopback DNS target exists
		// so the OS keeps sending queries to ctrld's listener (issue #533).
		ensureInterceptDNSTargetFn(p, systemNameservers)

		// Exempt DHCP nameservers from intercept filters so the OS resolver
		// can actually reach them on port 53.
		// The OS resolver queries the effective list, so the exemptions follow it.
		if len(resolverNameservers) > 0 {
			// Build exemptions without an Interface — DHCP servers are not VPN-specific,
			// so they only generate group-scoped pf rules (ctrld process only).
			exemptions := make([]vpnDNSExemption, 0, len(resolverNameservers))
			for _, s := range resolverNameservers {
				host := s
				if h, _, err := net.SplitHostPort(s); err == nil {
					host = h
				}
				exemptions = append(exemptions, vpnDNSExemption{Server: host})
			}
			mainLog.Load().Info().Msgf("DNS intercept recovery: exempting DHCP nameservers from filters: %v", exemptions)
			if err := p.exemptVPNDNSServers(exemptions); err != nil {
				mainLog.Load().Warn().Err(err).Msg("DNS intercept recovery: failed to exempt DHCP nameservers — recovery queries may fail")
			}
		}
	} else {
		// Traditional flow: remove DNS settings to expose DHCP nameservers
		recoveryResetDNSFn(p, false, false)

		// For an OS failure, reinitialize OS resolver nameservers immediately.
		if reason == RecoveryReasonOSFailure {
			mainLog.Load().Debug().Msg("OS resolver failure detected; reinitializing OS resolver nameservers")
			ns := ctrld.InitializeOsResolverWithReason(true, recoveryResolverReason)
			if len(ns) == 0 {
				mainLog.Load().Warn().Msg("No nameservers found for OS resolver; using existing values")
			} else {
				journal(mainLog.Load().Info()).Msgf("Reinitialized OS resolver with nameservers: %v", ns)
			}
		}
	}

	// Wait for the same upstream pool used to admit this recovery.
	recovered, err := waitForUpstreamRecoveryFn(p, recoveryCtx, upstreams, &diagnostic)
	if err != nil {
		if p.recoveryGen.Load() == gen {
			outcome = recoveryOutcomeCanceled
		}
		return
	}
	diagnostic.recoveredUpstream = recovered
	if !p.recoveryOwnsState(gen) {
		mainLog.Load().Debug().Msgf("Recovery generation %d was superseded after upstream success; skipping stale completion", gen)
		return
	}
	// The reset ends the outage, so the down time is read before it. The name
	// of the line is bounded, because an upstream key is operator text.
	journalName := journalUpstreamName(recovered)
	journal(mainLog.Load().Info()).Str("upstream", journalName).
		Int64("down_for_ms", p.um.downFor(recovered).Milliseconds()).
		Msgf("Upstream %q recovered; re-applying DNS settings", journalName)

	// Reset the upstream failure count and down state while this generation
	// still owns recovery completion.
	p.um.reset(recovered)

	if interceptRecovery {
		// Refresh VPN DNS routes in case VPN state changed during recovery.
		if p.vpnDNS != nil {
			p.vpnDNS.Refresh(true)
		}

		// Reinitialize OS resolver for the recovered state.
		if reason == RecoveryReasonNetworkChange {
			ns := ctrld.InitializeOsResolverWithReason(true, recoveryResolverReason)
			if len(ns) == 0 {
				mainLog.Load().Warn().Msg("No nameservers found for OS resolver during network-change recovery; using existing values")
			} else {
				journal(mainLog.Load().Info()).Msgf("Reinitialized OS resolver with nameservers: %v", ns)
			}
		}
	} else {
		var systemNameservers []string
		if dnsIntercept {
			// Intercept was requested but no interceptor was active when recovery
			// began. Rediscover on every recovery reason before retrying setDNS;
			// passing nil could make a successful retry install a loopback target
			// on a healthy DHCP network.
			systemNameservers = systemNameserversForInterceptRetry()
		} else if reason == RecoveryReasonNetworkChange {
			ns := ctrld.InitializeOsResolverWithReason(true, recoveryResolverReason)
			if len(ns) == 0 {
				mainLog.Load().Warn().Msg("No nameservers found for OS resolver during network-change recovery; using existing values")
			} else {
				journal(mainLog.Load().Info()).Msgf("Reinitialized OS resolver with nameservers: %v", ns)
			}
		}

		// Apply our DNS settings back. The snapshot that follows the end event
		// reports the interfaces.
		p.setDNS(systemNameservers)
	}

	if !p.completeRecovery(gen) {
		mainLog.Load().Debug().Msgf("Recovery generation %d was superseded during completion; preserving successor state", gen)
		return
	}
	outcome = recoveryOutcomeCompleted
	if interceptRecovery {
		journal(mainLog.Load().Info()).Msg("DNS intercept recovery complete: disabling DHCP bypass, resuming normal flow")
	}
}

// refreshOSResolverAfterRecoverySkip repairs stale OS resolver discovery without
// enabling bypass, changing host DNS, or clearing the monitor's failure state.
// Only a successful query establishes that the OS resolver recovered.
func (p *prog) refreshOSResolverAfterRecoverySkip(healthy string) {
	if !p.osRecoveryRefreshMu.TryLock() {
		return
	}
	defer p.osRecoveryRefreshMu.Unlock()

	now := networkEventsNowFn()
	if p.osRecoverySkipLogAt.IsZero() || healthy != p.osRecoverySkipUpstream || now.Sub(p.osRecoverySkipLogAt) >= 5*time.Minute {
		journal(mainLog.Load().Info()).Str("recovery_reason", recoveryReasonName(RecoveryReasonOSFailure)).
			Str("healthy_upstream", journalUpstreamName(healthy)).
			Msg("Recovery skipped: configured upstream is not marked down")
		p.osRecoverySkipLogAt = now
		p.osRecoverySkipUpstream = healthy
	}
	// Failed policy queries can arrive concurrently and at high volume. Retry
	// discovery on later traffic, but never run overlapping or per-query reads.
	if !p.osRecoveryRefreshAt.IsZero() && now.Sub(p.osRecoveryRefreshAt) < upstreamDownDelay {
		return
	}
	p.osRecoveryRefreshAt = now
	initializeOsResolverWithSystemNameserversFn(true, recoveryResolverReason)
}

// waitForUpstreamRecoveryFn is the seam of the upstream probe. A test drives
// the whole recovery flow without a query to a real upstream.
var waitForUpstreamRecoveryFn = (*prog).waitForUpstreamRecovery

var queryRecoveryFn = (*prog).handleRecovery

// waitForUpstreamRecovery checks the provided upstreams concurrently until one recovers.
// It returns the name of the recovered upstream or an error if the check times out.
func (p *prog) waitForUpstreamRecovery(ctx context.Context, upstreams map[string]*ctrld.UpstreamConfig, diagnostic *recoveryDiagnostic) (string, error) {
	recoveryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	recoveredCh := make(chan string, 1)
	var wg sync.WaitGroup

	mainLog.Load().Debug().Msgf("Starting upstream recovery check for %d upstreams", len(upstreams))
	defer func() {
		cancel()
		wg.Wait()
	}()

	for name, uc := range upstreams {
		wg.Add(1)
		go func(name string, uc *ctrld.UpstreamConfig) {
			defer wg.Done()
			mainLog.Load().Debug().Msgf("Starting recovery check loop for upstream: %s", name)
			attempts := 0
			unreachableStreak := 0
			var failures upstreamFailureLog
			for {
				select {
				case <-recoveryCtx.Done():
					mainLog.Load().Debug().Msgf("Context canceled for upstream %s", name)
					return
				default:
					attempts++
					// The owning recovery resets the monitor after this probe succeeds.
					err := p.checkUpstreamOnce(name, uc, &failures)
					if err == nil || errors.Is(err, errOsHealthcheckSuppressed) {
						mainLog.Load().Debug().Msgf("Upstream %s recovered successfully", name)
						select {
						case recoveredCh <- name:
							mainLog.Load().Debug().Msgf("Sent recovery notification for upstream %s", name)
							cancel()
						default:
							mainLog.Load().Debug().Msg("Recovery channel full, another upstream already recovered")
						}
						return
					}
					diagnostic.failure(err)
					// Back off the retry cadence for an unroutable endpoint so a
					// host with IPv6 up but no route to the IPv6 DoH endpoint does
					// not re-bootstrap/re-check every checkUpstreamBackoffSleep and
					// spam the log. The backoff is bounded (checkUpstreamUnreachableBackoffMax)
					// so the endpoint is still re-probed and recovers when the route
					// returns; any other failure resets to the base cadence.
					sleep := checkUpstreamBackoffSleep
					if ctrldnet.IsUnreachable(err) {
						unreachableStreak++
						sleep = unreachableRecoveryBackoff(unreachableStreak)
						mainLog.Load().Debug().Msgf("Upstream %s unreachable (streak %d), backing off %s before retry", name, unreachableStreak, sleep)
					} else {
						unreachableStreak = 0
						mainLog.Load().Debug().Msgf("Upstream %s check failed, sleeping before retry", name)
					}
					if !sleepWithContext(recoveryCtx, sleep) {
						return
					}

					// if this is the upstreamOS and it's the 3rd attempt (or multiple of 3),
					// we should try to reinit the OS resolver to ensure we can recover
					if name == upstreamOS && attempts%3 == 0 {
						mainLog.Load().Debug().Msgf("UpstreamOS check failed on attempt %d, reinitializing OS resolver", attempts)
						ns := ctrld.InitializeOsResolverWithReason(true, recoveryResolverReason)
						if len(ns) == 0 {
							mainLog.Load().Warn().Msg("No nameservers found for OS resolver; using existing values")
						} else {
							journal(mainLog.Load().Info()).Msgf("Reinitialized OS resolver with nameservers: %v", ns)
						}
					}
				}
			}
		}(name, uc)
	}

	var recovered string
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	select {
	case recovered = <-recoveredCh:
		if err := ctx.Err(); err != nil {
			return "", err
		}
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return recovered, nil
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// buildRecoveryUpstreams constructs the map of upstream configurations to test.
// OS failures use configured non-OS upstreams for both admission and recovery,
// excluding generated Internal Domain resolvers. OS-only configurations retain
// the OS recovery path. Other recovery reasons retain their configured pool.
func (p *prog) buildRecoveryUpstreams(reason RecoveryReason) map[string]*ctrld.UpstreamConfig {
	upstreams := make(map[string]*ctrld.UpstreamConfig)
	switch reason {
	case RecoveryReasonOSFailure:
		for k, uc := range p.cfg.Upstream {
			name := upstreamPrefix + k
			if uc != nil && uc.Type != ctrld.ResolverTypeOS && !isGeneratedInternalDomainUpstream(uc) {
				upstreams[name] = uc
			}
		}
		if len(upstreams) == 0 {
			upstreams[upstreamOS] = osUpstreamConfig
		}
	case RecoveryReasonNetworkChange, RecoveryReasonRegularFailure:
		// Use all configured upstreams except any OS type.
		for k, uc := range p.cfg.Upstream {
			if uc != nil && uc.Type != ctrld.ResolverTypeOS {
				upstreams[upstreamPrefix+k] = uc
			}
		}
		// An OS-only configuration still needs a recovery worker. Do not add
		// OS to mixed pools: their existing recovery boundaries stay intact.
		if len(upstreams) == 0 {
			upstreams[upstreamOS] = osUpstreamConfig
		}
	}
	return upstreams
}

// ValidateDefaultLocalIPsFromDelta checks if the default local IPv4 and IPv6 stored
// are still present in the new network state (provided by delta.New).
// If a stored default IP is no longer active, it resets that default (sets it to nil)
// so that it won't be used in subsequent custom dialer contexts.
// Deprecated: retained for callers of the existing exported cli API.
// The network monitor uses transition-aware validation instead.
func ValidateDefaultLocalIPsFromDelta(newState *netmon.State) {
	validateDefaultLocalIPsFromDelta(newState, 0)
}

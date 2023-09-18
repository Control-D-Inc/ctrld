package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"tailscale.com/net/interfaces"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

const (
	staleTTL = 60 * time.Second
	// EDNS0_OPTION_MAC is dnsmasq EDNS0 code for adding mac option.
	// https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=blob;f=src/dns-protocol.h;h=76ac66a8c28317e9c121a74ab5fd0e20f6237dc8;hb=HEAD#l81
	// This is also dns.EDNS0LOCALSTART, but define our own constant here for clarification.
	EDNS0_OPTION_MAC = 0xFDE9
)

var osUpstreamConfig = &ctrld.UpstreamConfig{
	Name:    "OS resolver",
	Type:    ctrld.ResolverTypeOS,
	Timeout: 2000,
}

func (p *prog) serveDNS(listenerNum string) error {
	listenerConfig := p.cfg.Listener[listenerNum]
	// make sure ip is allocated
	if allocErr := p.allocateIP(listenerConfig.IP); allocErr != nil {
		mainLog.Load().Error().Err(allocErr).Str("ip", listenerConfig.IP).Msg("serveUDP: failed to allocate listen ip")
		return allocErr
	}
	var failoverRcodes []int
	if listenerConfig.Policy != nil {
		failoverRcodes = listenerConfig.Policy.FailoverRcodeNumbers
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		p.sema.acquire()
		defer p.sema.release()
		q := m.Question[0]
		domain := canonicalName(q.Name)
		reqId := requestID()
		remoteIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		ci := p.getClientInfo(remoteIP, m)
		remoteAddr := spoofRemoteAddr(w.RemoteAddr(), ci)
		fmtSrcToDest := fmtRemoteToLocal(listenerNum, remoteAddr.String(), w.LocalAddr().String())
		t := time.Now()
		ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, reqId)
		ctrld.Log(ctx, mainLog.Load().Debug(), "%s received query: %s %s", fmtSrcToDest, dns.TypeToString[q.Qtype], domain)
		upstreams, matched := p.upstreamFor(ctx, listenerNum, listenerConfig, remoteAddr, domain)
		var answer *dns.Msg
		if !matched && listenerConfig.Restricted {
			answer = new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)
		} else {
			answer = p.proxy(ctx, upstreams, failoverRcodes, m, ci)
			rtt := time.Since(t)
			ctrld.Log(ctx, mainLog.Load().Debug(), "received response of %d bytes in %s", answer.Len(), rtt)
		}
		if err := w.WriteMsg(answer); err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "serveUDP: failed to send DNS response to client")
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
				for _, addr := range rfc1918Addresses() {
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
			select {
			case err := <-errCh:
				return err
			case <-time.After(5 * time.Second):
				p.started <- struct{}{}
			}
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
func (p *prog) upstreamFor(ctx context.Context, defaultUpstreamNum string, lc *ctrld.ListenerConfig, addr net.Addr, domain string) ([]string, bool) {
	upstreams := []string{"upstream." + defaultUpstreamNum}
	matchedPolicy := "no policy"
	matchedNetwork := "no network"
	matchedRule := "no rule"
	matched := false

	defer func() {
		if !matched && lc.Restricted {
			ctrld.Log(ctx, mainLog.Load().Info(), "query refused, %s does not match any network policy", addr.String())
			return
		}
		if matched {
			ctrld.Log(ctx, mainLog.Load().Info(), "%s, %s, %s -> %v", matchedPolicy, matchedNetwork, matchedRule, upstreams)
		} else {
			ctrld.Log(ctx, mainLog.Load().Info(), "no explicit policy matched, using default routing -> %v", upstreams)
		}
	}()

	if lc.Policy == nil {
		return upstreams, false
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
				return upstreams, matched
			}
		}
	}

	if matched {
		do(networkTargets)
	}

	return upstreams, matched
}

func (p *prog) proxy(ctx context.Context, upstreams []string, failoverRcodes []int, msg *dns.Msg, ci *ctrld.ClientInfo) *dns.Msg {
	var staleAnswer *dns.Msg
	serveStaleCache := p.cache != nil && p.cfg.Service.CacheServeStale
	upstreamConfigs := p.upstreamConfigsFromUpstreamNumbers(upstreams)
	if len(upstreamConfigs) == 0 {
		upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
		upstreams = []string{"upstream.os"}
	}
	// Inverse query should not be cached: https://www.rfc-editor.org/rfc/rfc1035#section-7.4
	if p.cache != nil && msg.Question[0].Qtype != dns.TypePTR {
		for _, upstream := range upstreams {
			cachedValue := p.cache.Get(dnscache.NewKey(msg, upstream))
			if cachedValue == nil {
				continue
			}
			answer := cachedValue.Msg.Copy()
			answer.SetRcode(msg, answer.Rcode)
			now := time.Now()
			if cachedValue.Expire.After(now) {
				ctrld.Log(ctx, mainLog.Load().Debug(), "hit cached response")
				setCachedAnswerTTL(answer, now, cachedValue.Expire)
				return answer
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
		if upstreamConfig.UpstreamSendClientInfo() && ci != nil {
			ctrld.Log(ctx, mainLog.Load().Debug(), "including client info with the request")
			ctx = context.WithValue(ctx, ctrld.ClientInfoCtxKey{}, ci)
		}
		answer, err := resolve1(n, upstreamConfig, msg)
		if err != nil {
			ctrld.Log(ctx, mainLog.Load().Error().Err(err), "failed to resolve query")
			return nil
		}
		return answer
	}
	for n, upstreamConfig := range upstreamConfigs {
		if upstreamConfig == nil {
			continue
		}
		answer := resolve(n, upstreamConfig, msg)
		if answer == nil {
			if serveStaleCache && staleAnswer != nil {
				ctrld.Log(ctx, mainLog.Load().Debug(), "serving stale cached response")
				now := time.Now()
				setCachedAnswerTTL(staleAnswer, now, now.Add(staleTTL))
				return staleAnswer
			}
			continue
		}
		if answer.Rcode != dns.RcodeSuccess && len(upstreamConfigs) > 1 && containRcode(failoverRcodes, answer.Rcode) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "failover rcode matched, process to next upstream")
			continue
		}

		// set compression, as it is not set by default when unpacking
		answer.Compress = true

		if p.cache != nil {
			ttl := ttlFromMsg(answer)
			now := time.Now()
			expired := now.Add(time.Duration(ttl) * time.Second)
			if cachedTTL := p.cfg.Service.CacheTTLOverride; cachedTTL > 0 {
				expired = now.Add(time.Duration(cachedTTL) * time.Second)
			}
			setCachedAnswerTTL(answer, now, expired)
			p.cache.Add(dnscache.NewKey(msg, upstreams[n]), dnscache.NewValue(answer, expired))
			ctrld.Log(ctx, mainLog.Load().Debug(), "add cached response")
		}
		return answer
	}
	ctrld.Log(ctx, mainLog.Load().Error(), "all upstreams failed")
	answer := new(dns.Msg)
	answer.SetRcode(msg, dns.RcodeServerFailure)
	return answer
}

func (p *prog) upstreamConfigsFromUpstreamNumbers(upstreams []string) []*ctrld.UpstreamConfig {
	upstreamConfigs := make([]*ctrld.UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		upstreamNum := strings.TrimPrefix(upstream, "upstream.")
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

func wildcardMatches(wildcard, domain string) bool {
	// Wildcard match.
	wildCardParts := strings.Split(wildcard, "*")
	if len(wildCardParts) != 2 {
		return false
	}

	switch {
	case len(wildCardParts[0]) > 0 && len(wildCardParts[1]) > 0:
		// Domain must match both prefix and suffix.
		return strings.HasPrefix(domain, wildCardParts[0]) && strings.HasSuffix(domain, wildCardParts[1])

	case len(wildCardParts[1]) > 0:
		// Only suffix must match.
		return strings.HasSuffix(domain, wildCardParts[1])

	case len(wildCardParts[0]) > 0:
		// Only prefix must match.
		return strings.HasPrefix(domain, wildCardParts[0])
	}

	return false
}

func fmtRemoteToLocal(listenerNum, remote, local string) string {
	return fmt.Sprintf("%s -> listener.%s: %s:", remote, listenerNum, local)
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

	waitLock := sync.Mutex{}
	waitLock.Lock()
	s.NotifyStartedFunc = waitLock.Unlock

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		if err := s.ListenAndServe(); err != nil {
			waitLock.Unlock()
			mainLog.Load().Error().Err(err).Msgf("could not listen and serve on: %s", s.Addr)
			errCh <- err
		}
	}()
	waitLock.Lock()
	return s, errCh
}

func (p *prog) getClientInfo(remoteIP string, msg *dns.Msg) *ctrld.ClientInfo {
	ci := &ctrld.ClientInfo{}
	if p.appCallback != nil {
		ci.IP = p.appCallback.LanIp()
		ci.Mac = p.appCallback.MacAddress()
		ci.Hostname = p.appCallback.HostName()
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
	// like VPN/Wireguard clients, so we use whatever MAC address associated with remoteIP
	// (most likely 127.0.0.1), and ci.IP as hostname, so we can distinguish those clients.
	if ci.Mac == "" {
		ci.Mac = p.ciTable.LookupMac(remoteIP)
		if hostname := p.ciTable.LookupHostname(ci.IP, ""); hostname != "" {
			ci.Hostname = hostname
		} else {
			ci.Hostname = ci.IP
			p.ciTable.StoreVPNClient(ci)
		}
	} else {
		ci.Hostname = p.ciTable.LookupHostname(ci.IP, ci.Mac)
	}
	return ci
}

func needRFC1918Listeners(lc *ctrld.ListenerConfig) bool {
	return lc.IP == "127.0.0.1" && lc.Port == 53
}

func rfc1918Addresses() []string {
	var res []string
	interfaces.ForeachInterface(func(i interfaces.Interface, prefixes []netip.Prefix) {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || !ipNet.IP.IsPrivate() {
				continue
			}
			res = append(res, ipNet.IP.String())
		}
	})
	return res
}

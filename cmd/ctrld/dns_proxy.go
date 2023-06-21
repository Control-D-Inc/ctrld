package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go4.org/mem"
	"golang.org/x/sync/errgroup"
	"tailscale.com/util/lineread"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/router"
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
		mainLog.Error().Err(allocErr).Str("ip", listenerConfig.IP).Msg("serveUDP: failed to allocate listen ip")
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
		remoteAddr := spoofRemoteAddr(w.RemoteAddr(), router.GetClientInfoByMac(macFromMsg(m)))
		fmtSrcToDest := fmtRemoteToLocal(listenerNum, remoteAddr.String(), w.LocalAddr().String())
		t := time.Now()
		ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, reqId)
		ctrld.Log(ctx, mainLog.Debug(), "%s received query: %s %s", fmtSrcToDest, dns.TypeToString[q.Qtype], domain)
		upstreams, matched := p.upstreamFor(ctx, listenerNum, listenerConfig, remoteAddr, domain)
		var answer *dns.Msg
		if !matched && listenerConfig.Restricted {
			answer = new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)
		} else {
			answer = p.proxy(ctx, upstreams, failoverRcodes, m)
			rtt := time.Since(t)
			ctrld.Log(ctx, mainLog.Debug(), "received response of %d bytes in %s", answer.Len(), rtt)
		}
		if err := w.WriteMsg(answer); err != nil {
			ctrld.Log(ctx, mainLog.Error().Err(err), "serveUDP: failed to send DNS response to client")
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
				case <-ctx.Done():
				case err := <-errCh:
					// Local ipv6 listener should not terminate ctrld.
					// It's a workaround for a quirk on Windows.
					mainLog.Warn().Err(err).Msg("local ipv6 listener failed")
				}
				return nil
			})
		}
		g.Go(func() error {
			s, errCh := runDNSServer(dnsListenAddress(listenerNum, listenerConfig), proto, handler)
			defer s.Shutdown()
			if listenerConfig.Port == 0 {
				switch s.Net {
				case "udp":
					mainLog.Info().Msgf("Random port chosen for udp listener.%s: %s", listenerNum, s.PacketConn.LocalAddr())
				case "tcp":
					mainLog.Info().Msgf("Random port chosen for tcp listener.%s: %s", listenerNum, s.Listener.Addr())
				}
			}
			select {
			case err := <-errCh:
				return err
			case <-time.After(5 * time.Second):
				p.started <- struct{}{}
			}
			select {
			case <-ctx.Done():
				return nil
			case err := <-errCh:
				return err
			}
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
			ctrld.Log(ctx, mainLog.Info(), "query refused, %s does not match any network policy", addr.String())
			return
		}
		ctrld.Log(ctx, mainLog.Info(), "%s, %s, %s -> %v", matchedPolicy, matchedNetwork, matchedRule, upstreams)
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

func (p *prog) proxy(ctx context.Context, upstreams []string, failoverRcodes []int, msg *dns.Msg) *dns.Msg {
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
				ctrld.Log(ctx, mainLog.Debug(), "hit cached response")
				setCachedAnswerTTL(answer, now, cachedValue.Expire)
				return answer
			}
			staleAnswer = answer
		}
	}
	resolve1 := func(n int, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) (*dns.Msg, error) {
		ctrld.Log(ctx, mainLog.Debug(), "sending query to %s: %s", upstreams[n], upstreamConfig.Name)
		dnsResolver, err := ctrld.NewResolver(upstreamConfig)
		if err != nil {
			ctrld.Log(ctx, mainLog.Error().Err(err), "failed to create resolver")
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
		if upstreamConfig.UpstreamSendClientInfo() {
			ci := router.GetClientInfoByMac(macFromMsg(msg))
			if ci != nil {
				ctrld.Log(ctx, mainLog.Debug(), "including client info with the request")
				ctx = context.WithValue(ctx, ctrld.ClientInfoCtxKey{}, ci)
			}
		}
		answer, err := resolve1(n, upstreamConfig, msg)
		if err != nil {
			ctrld.Log(ctx, mainLog.Error().Err(err), "failed to resolve query")
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
				ctrld.Log(ctx, mainLog.Debug(), "serving stale cached response")
				now := time.Now()
				setCachedAnswerTTL(staleAnswer, now, now.Add(staleTTL))
				return staleAnswer
			}
			continue
		}
		if answer.Rcode != dns.RcodeSuccess && len(upstreamConfigs) > 1 && containRcode(failoverRcodes, answer.Rcode) {
			ctrld.Log(ctx, mainLog.Debug(), "failover rcode matched, process to next upstream")
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
			ctrld.Log(ctx, mainLog.Debug(), "add cached response")
		}
		return answer
	}
	ctrld.Log(ctx, mainLog.Error(), "all upstreams failed")
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

func dnsListenAddress(lcNum string, lc *ctrld.ListenerConfig) string {
	addr := net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port))
	// If we are inside container and the listener address is localhost,
	// Change it to 0.0.0.0:53, so user can expose the port to outside.
	if addr == "127.0.0.1:53" && cdUID != "" && inContainer() {
		return "0.0.0.0:53"
	}
	return net.JoinHostPort(lc.IP, strconv.Itoa(lc.Port))
}

func macFromMsg(msg *dns.Msg) string {
	if opt := msg.IsEdns0(); opt != nil {
		for _, s := range opt.Option {
			switch e := s.(type) {
			case *dns.EDNS0_LOCAL:
				if e.Code == EDNS0_OPTION_MAC {
					return net.HardwareAddr(e.Data).String()
				}
			}
		}
	}
	return ""
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
			mainLog.Error().Err(err).Msgf("could not listen and serve on: %s", s.Addr)
			errCh <- err
		}
	}()
	waitLock.Lock()
	return s, errCh
}

// inContainer reports whether we're running in a container.
//
// Copied from https://github.com/tailscale/tailscale/blob/v1.42.0/hostinfo/hostinfo.go#L260
// with modification for ctrld usage.
func inContainer() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	var ret bool
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		// See https://github.com/cri-o/cri-o/issues/5461
		return true
	}
	lineread.File("/proc/1/cgroup", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("/docker/")) ||
			mem.Contains(mem.B(line), mem.S("/lxc/")) {
			ret = true
			return io.EOF // arbitrary non-nil error to stop loop
		}
		return nil
	})
	lineread.File("/proc/mounts", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("fuse.lxcfs")) {
			ret = true
			return io.EOF
		}
		return nil
	})
	return ret
}

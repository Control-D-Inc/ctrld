package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

func (p *prog) serveUDP(listenerNum string) error {
	listenerConfig := p.cfg.Listener[listenerNum]
	// make sure ip is allocated
	if allocErr := p.allocateIP(listenerConfig.IP); allocErr != nil {
		mainLog.Error().Err(allocErr).Str("ip", listenerConfig.IP).Msg("serveUDP: failed to allocate listen ip")
		return allocErr
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		domain := canonicalName(m.Question[0].Name)
		reqId := requestID()
		fmtSrcToDest := fmtRemoteToLocal(listenerNum, w.RemoteAddr().String(), w.LocalAddr().String())
		t := time.Now()
		ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, reqId)
		ctrld.Log(ctx, proxyLog.Debug(), "%s received query: %s", fmtSrcToDest, domain)
		upstreams, matched := p.upstreamFor(ctx, listenerNum, listenerConfig, w.RemoteAddr(), domain)
		var answer *dns.Msg
		if !matched && listenerConfig.Restricted {
			answer = new(dns.Msg)
			answer.SetRcode(m, dns.RcodeRefused)

		} else {
			answer = p.proxy(ctx, upstreams, m)
			rtt := time.Since(t)
			ctrld.Log(ctx, proxyLog.Debug(), "received response of %d bytes in %s", answer.Len(), rtt)
		}
		if err := w.WriteMsg(answer); err != nil {
			ctrld.Log(ctx, mainLog.Error().Err(err), "serveUDP: failed to send DNS response to client")
		}
	})
	s := &dns.Server{
		Addr:    net.JoinHostPort(listenerConfig.IP, strconv.Itoa(listenerConfig.Port)),
		Net:     "udp",
		Handler: handler,
	}
	return s.ListenAndServe()
}

func (p *prog) upstreamFor(ctx context.Context, defaultUpstreamNum string, lc *ctrld.ListenerConfig, addr net.Addr, domain string) ([]string, bool) {
	upstreams := []string{"upstream." + defaultUpstreamNum}
	matchedPolicy := "no policy"
	matchedNetwork := "no network"
	matchedRule := "no rule"
	matched := false

	defer func() {
		if !matched && lc.Restricted {
			ctrld.Log(ctx, proxyLog.Info(), "query refused, %s does not match any network policy", addr.String())
			return
		}
		ctrld.Log(ctx, proxyLog.Info(), "%s, %s, %s -> %v", matchedPolicy, matchedNetwork, matchedRule, upstreams)
	}()

	if lc.Policy == nil {
		return upstreams, false
	}

	do := func(policyUpstreams []string) {
		upstreams = append([]string(nil), policyUpstreams...)
	}

	for _, rule := range lc.Policy.Rules {
		// There's only one entry per rule, config validation ensures this.
		for source, targets := range rule {
			if source == domain || wildcardMatches(source, domain) {
				matchedPolicy = lc.Policy.Name
				matchedRule = source
				do(targets)
				matched = true
				return upstreams, matched
			}
		}
	}

	var sourceIP net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		sourceIP = addr.IP
	case *net.TCPAddr:
		sourceIP = addr.IP
	}
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
					do(targets)
					matched = true
					return upstreams, matched
				}
			}
		}
	}

	return upstreams, matched
}

func (p *prog) proxy(ctx context.Context, upstreams []string, msg *dns.Msg) *dns.Msg {
	upstreamConfigs := p.upstreamConfigsFromUpstreamNumbers(upstreams)
	resolve := func(n int, upstreamConfig *ctrld.UpstreamConfig, msg *dns.Msg) *dns.Msg {
		ctrld.Log(ctx, proxyLog.Debug(), "sending query to %s: %s", upstreams[n], upstreamConfig.Name)
		dnsResolver, err := ctrld.NewResolver(upstreamConfig)
		if err != nil {
			ctrld.Log(ctx, proxyLog.Error().Err(err), "failed to create resolver")
			return nil
		}
		if upstreamConfig.Timeout > 0 {
			timeoutCtx, cancel := context.WithTimeout(ctx, time.Millisecond*time.Duration(upstreamConfig.Timeout))
			defer cancel()
			ctx = timeoutCtx
		}
		answer, err := dnsResolver.Resolve(ctx, msg)
		if err != nil {
			ctrld.Log(ctx, proxyLog.Error().Err(err), "failed to resolve query")
			return nil
		}
		return answer
	}
	for n, upstreamConfig := range upstreamConfigs {
		if answer := resolve(n, upstreamConfig, msg); answer != nil {
			return answer
		}
	}
	ctrld.Log(ctx, proxyLog.Error(), "all upstreams failed")
	answer := new(dns.Msg)
	answer.SetRcode(msg, dns.RcodeServerFailure)
	return answer
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

func (p *prog) upstreamConfigsFromUpstreamNumbers(upstreams []string) []*ctrld.UpstreamConfig {
	upstreamConfigs := make([]*ctrld.UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		upstreamNum := strings.TrimPrefix(upstream, "upstream.")
		upstreamConfigs = append(upstreamConfigs, p.cfg.Upstream[upstreamNum])
	}
	if len(upstreamConfigs) == 0 {
		upstreamConfigs = []*ctrld.UpstreamConfig{osUpstreamConfig}
	}
	return upstreamConfigs
}

func requestID() string {
	b := make([]byte, 3) // 6 chars
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

var osUpstreamConfig = &ctrld.UpstreamConfig{
	Name: "OS resolver",
	Type: "os",
}

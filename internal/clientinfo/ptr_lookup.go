package clientinfo

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

type ptrDiscover struct {
	hostname sync.Map // ip => hostname
	resolver ctrld.Resolver
}

func (p *ptrDiscover) refresh() error {
	p.hostname.Range(func(key, value any) bool {
		ip := key.(string)
		if name := p.lookupHostname(ip); name != "" {
			p.hostname.Store(ip, name)
		}
		return true
	})
	return nil
}

func (p *ptrDiscover) LookupHostnameByIP(ip string) string {
	if val, ok := p.hostname.Load(ip); ok {
		return val.(string)
	}
	return p.lookupHostname(ip)
}
func (p *ptrDiscover) LookupHostnameByMac(mac string) string {
	return ""
}

func (p *ptrDiscover) String() string {
	return "ptr"
}

func (p *ptrDiscover) lookupHostname(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	msg := new(dns.Msg)
	addr, err := dns.ReverseAddr(ip)
	if err != nil {
		ctrld.ProxyLog.Error().Err(err).Msg("invalid ip address")
		return ""
	}
	msg.SetQuestion(addr, dns.TypePTR)
	ans, err := p.resolver.Resolve(ctx, msg)
	if err != nil {
		ctrld.ProxyLog.Error().Err(err).Msg("could not lookup IP")
		return ""
	}
	for _, rr := range ans.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			hostname := normalizeHostname(ptr.Ptr)
			p.hostname.Store(ip, hostname)
			return hostname
		}
	}
	return ""
}

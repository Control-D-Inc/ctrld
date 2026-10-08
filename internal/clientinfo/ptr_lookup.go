package clientinfo

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld"
)

type ptrDiscover struct {
	hostname   sync.Map // ip => hostname
	resolver   ctrld.Resolver
	serverDown atomic.Bool
	logger     *ctrld.Logger
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

func (p *ptrDiscover) List() []string {
	if p == nil {
		return nil
	}
	var ips []string
	p.hostname.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

func (p *ptrDiscover) lookupHostnameFromCache(ip string) string {
	if val, ok := p.hostname.Load(ip); ok {
		return val.(string)
	}
	return ""
}

func (p *ptrDiscover) lookupHostname(ip string) string {
	// If nameserver is down, do nothing.
	if p.serverDown.Load() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	msg := new(dns.Msg)
	addr, err := dns.ReverseAddr(ip)
	if err != nil {
		p.logger.Info().Str("discovery", "ptr").Err(err).Msg("Invalid ip address")
		return ""
	}
	msg.SetQuestion(addr, dns.TypePTR)
	ans, err := p.resolver.Resolve(ctx, msg)
	if err != nil {
		if p.serverDown.CompareAndSwap(false, true) {
			p.logger.Info().Str("discovery", "ptr").Err(err).Msg("Could not perform ptr lookup")
			go p.checkServer()
		}
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

func (p *ptrDiscover) lookupIPByHostname(name string, v6 bool) string {
	if p == nil {
		return ""
	}
	var ip string
	p.hostname.Range(func(key, value any) bool {
		if value == name {
			if addr, err := netip.ParseAddr(key.(string)); err == nil && addr.Is6() == v6 {
				ip = addr.String()
				// Continue searching if this is a loopback address
				// We prefer non-loopback addresses as they're more likely to be the actual client IP
				return addr.IsLoopback() // Continue searching if this is loopback address.
			}
		}
		return true
	})
	return ip
}

// checkServer monitors if the resolver can reach its nameserver. When the nameserver
// is reachable, set p.serverDown to false, so p.lookupHostname can continue working.
func (p *ptrDiscover) checkServer() {
	bo := backoff.NewBackoff("ptrDiscover", func(format string, args ...any) {}, time.Minute*5)
	m := (&ctrld.UpstreamConfig{}).VerifyMsg()
	ping := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := p.resolver.Resolve(ctx, m)
		return err
	}
	for {
		if err := ping(); err != nil {
			bo.BackOff(context.Background(), err)
			continue
		}
		break
	}
	p.serverDown.Store(false)
}

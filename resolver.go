package ctrld

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	ResolverTypeDOH    = "doh"
	ResolverTypeDOH3   = "doh3"
	ResolverTypeDOT    = "dot"
	ResolverTypeDOQ    = "doq"
	ResolverTypeOS     = "os"
	ResolverTypeLegacy = "legacy"
)

var bootstrapDNS = "76.76.2.0"
var or = &osResolver{nameservers: nameservers()}

// Resolver is the interface that wraps the basic DNS operations.
//
// Resolve resolves the DNS query, return the result and the corresponding error.
type Resolver interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

var errUnknownResolver = errors.New("unknown resolver")

// NewResolver creates a Resolver based on the given upstream config.
func NewResolver(uc *UpstreamConfig) (Resolver, error) {
	typ := uc.Type
	switch typ {
	case ResolverTypeDOH, ResolverTypeDOH3:
		return newDohResolver(uc), nil
	case ResolverTypeDOT:
		return &dotResolver{uc: uc}, nil
	case ResolverTypeDOQ:
		return &doqResolver{uc: uc}, nil
	case ResolverTypeOS:
		return or, nil
	case ResolverTypeLegacy:
		return &legacyResolver{uc: uc}, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnknownResolver, typ)
}

type osResolver struct {
	nameservers []string
}

type osResolverResult struct {
	answer *dns.Msg
	err    error
}

// Resolve performs DNS resolvers using OS default nameservers. Nameserver is chosen from
// available nameservers with a roundrobin algorithm.
func (o *osResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	numServers := len(o.nameservers)
	if numServers == 0 {
		return nil, errors.New("no nameservers available")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dnsClient := &dns.Client{Net: "udp"}
	ch := make(chan *osResolverResult, numServers)
	var wg sync.WaitGroup
	wg.Add(len(o.nameservers))
	go func() {
		wg.Wait()
		close(ch)
	}()
	for _, server := range o.nameservers {
		go func(server string) {
			defer wg.Done()
			answer, _, err := dnsClient.ExchangeContext(ctx, msg.Copy(), server)
			ch <- &osResolverResult{answer: answer, err: err}
		}(server)
	}

	errs := make([]error, 0, numServers)
	for res := range ch {
		if res.err == nil {
			cancel()
			return res.answer, res.err
		}
		errs = append(errs, res.err)
	}

	return nil, errors.Join(errs...)
}

func newDialer(dnsAddress string) *net.Dialer {
	return &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, dnsAddress)
			},
		},
	}
}

type legacyResolver struct {
	uc *UpstreamConfig
}

func (r *legacyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// See comment in (*dotResolver).resolve method.
	dialer := newDialer(net.JoinHostPort(bootstrapDNS, "53"))
	dnsTyp := uint16(0)
	if len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	_, udpNet := r.uc.netForDNSType(dnsTyp)
	dnsClient := &dns.Client{
		Net:    udpNet,
		Dialer: dialer,
	}
	answer, _, err := dnsClient.ExchangeContext(ctx, msg, r.uc.Endpoint)
	return answer, err
}

// LookupIP looks up host using OS resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(domain string) []string {
	return lookupIP(domain, -1, true)
}

func lookupIP(domain string, timeout int, withBootstrapDNS bool) (ips []string) {
	resolver := &osResolver{nameservers: nameservers()}
	if withBootstrapDNS {
		resolver.nameservers = append([]string{net.JoinHostPort(bootstrapDNS, "53")}, resolver.nameservers...)
	}
	ProxyLog.Debug().Msgf("Resolving %q using bootstrap DNS %q", domain, resolver.nameservers)
	timeoutMs := 2000
	if timeout > 0 && timeout < timeoutMs {
		timeoutMs = timeoutMs
	}
	questionDomain := dns.Fqdn(domain)
	ipFromRecord := func(record dns.RR) string {
		switch ar := record.(type) {
		case *dns.A:
			if ar.Hdr.Name != questionDomain {
				return ""
			}
			return ar.A.String()
		case *dns.AAAA:
			if ar.Hdr.Name != questionDomain {
				return ""
			}
			return ar.AAAA.String()
		}
		return ""
	}

	lookup := func(dnsType uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
		m := new(dns.Msg)
		m.SetQuestion(questionDomain, dnsType)
		m.RecursionDesired = true

		r, err := resolver.Resolve(ctx, m)
		if err != nil {
			ProxyLog.Error().Err(err).Msgf("could not lookup %q record for domain %q", dns.TypeToString[dnsType], domain)
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			ProxyLog.Error().Msgf("could not resolve domain %q, return code: %s", domain, dns.RcodeToString[r.Rcode])
			return
		}
		if len(r.Answer) == 0 {
			ProxyLog.Error().Msg("no answer from OS resolver")
			return
		}
		for _, a := range r.Answer {
			if ip := ipFromRecord(a); ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	// Find all A, AAAA records of the domain.
	for _, dnsType := range []uint16{dns.TypeAAAA, dns.TypeA} {
		lookup(dnsType)
	}
	return ips
}

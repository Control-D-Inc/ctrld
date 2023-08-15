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
	// ResolverTypeDOH specifies DoH resolver.
	ResolverTypeDOH = "doh"
	// ResolverTypeDOH3 specifies DoH3 resolver.
	ResolverTypeDOH3 = "doh3"
	// ResolverTypeDOT specifies DoT resolver.
	ResolverTypeDOT = "dot"
	// ResolverTypeDOQ specifies DoQ resolver.
	ResolverTypeDOQ = "doq"
	// ResolverTypeOS specifies OS resolver.
	ResolverTypeOS = "os"
	// ResolverTypeLegacy specifies legacy resolver.
	ResolverTypeLegacy = "legacy"
)

var bootstrapDNS = "76.76.2.0"
var or = &osResolver{nameservers: nameservers()}

func init() {
	if len(or.nameservers) == 0 {
		// Add bootstrap DNS in case we did not find any.
		or.nameservers = []string{net.JoinHostPort(bootstrapDNS, "53")}
	}
}

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

type legacyResolver struct {
	uc *UpstreamConfig
}

func (r *legacyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// See comment in (*dotResolver).resolve method.
	dialer := newDialer(net.JoinHostPort(bootstrapDNS, "53"))
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	_, udpNet := r.uc.netForDNSType(dnsTyp)
	dnsClient := &dns.Client{
		Net:    udpNet,
		Dialer: dialer,
	}
	endpoint := r.uc.Endpoint
	if r.uc.BootstrapIP != "" {
		dnsClient.Net = "udp"
		_, port, _ := net.SplitHostPort(endpoint)
		endpoint = net.JoinHostPort(r.uc.BootstrapIP, port)
	}

	answer, _, err := dnsClient.ExchangeContext(ctx, msg, endpoint)
	return answer, err
}

type dummyResolver struct{}

func (d dummyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	ans := new(dns.Msg)
	ans.SetReply(msg)
	return ans, nil
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
	ProxyLogger.Load().Debug().Msgf("resolving %q using bootstrap DNS %q", domain, resolver.nameservers)
	timeoutMs := 2000
	if timeout > 0 && timeout < timeoutMs {
		timeoutMs = timeout
	}
	questionDomain := dns.Fqdn(domain)

	// Getting the real target domain name from CNAME if presents.
	targetDomain := func(answers []dns.RR) string {
		for _, a := range answers {
			switch ar := a.(type) {
			case *dns.CNAME:
				return ar.Target
			}
		}
		return questionDomain
	}
	// Getting ip address from A or AAAA record.
	ipFromRecord := func(record dns.RR, target string) string {
		switch ar := record.(type) {
		case *dns.A:
			if ar.Hdr.Name != target || len(ar.A) == 0 {
				return ""
			}
			return ar.A.String()
		case *dns.AAAA:
			if ar.Hdr.Name != target || len(ar.AAAA) == 0 {
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
			ProxyLogger.Load().Error().Err(err).Msgf("could not lookup %q record for domain %q", dns.TypeToString[dnsType], domain)
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			ProxyLogger.Load().Error().Msgf("could not resolve domain %q, return code: %s", domain, dns.RcodeToString[r.Rcode])
			return
		}
		if len(r.Answer) == 0 {
			ProxyLogger.Load().Error().Msg("no answer from OS resolver")
			return
		}
		target := targetDomain(r.Answer)
		for _, a := range r.Answer {
			if ip := ipFromRecord(a, target); ip != "" {
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

// NewBootstrapResolver returns an OS resolver, which use following nameservers:
//
//   - Gateway IP address (depends on OS).
//   - Input servers.
func NewBootstrapResolver(servers ...string) Resolver {
	resolver := &osResolver{nameservers: nameservers()}
	resolver.nameservers = append([]string{net.JoinHostPort(bootstrapDNS, "53")}, resolver.nameservers...)
	for _, ns := range servers {
		resolver.nameservers = append([]string{net.JoinHostPort(ns, "53")}, resolver.nameservers...)
	}
	return resolver
}

// NewPrivateResolver returns an OS resolver, which includes only private DNS servers.
// This is useful for doing PTR lookup in LAN network.
func NewPrivateResolver() Resolver {
	nss := nameservers()
	n := 0
	for _, ns := range nss {
		host, _, _ := net.SplitHostPort(ns)
		ip := net.ParseIP(host)
		if ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
			nss[n] = ns
			n++
		}
	}
	nss = nss[:n]
	if len(nss) == 0 {
		return &dummyResolver{}
	}
	resolver := &osResolver{nameservers: nss}
	return resolver
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

package ctrld

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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

// Resolver is the interface that wraps the basic DNS operations.
//
// Resolve resolves the DNS query, return the result and the corresponding error.
type Resolver interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

var errUnknownResolver = errors.New("unknown resolver")

// NewResolver creates a Resolver based on the given upstream config.
func NewResolver(uc *UpstreamConfig) (Resolver, error) {
	typ, endpoint := uc.Type, uc.Endpoint
	switch typ {
	case ResolverTypeDOH, ResolverTypeDOH3:
		return newDohResolver(uc), nil
	case ResolverTypeDOT:
		return &dotResolver{uc: uc}, nil
	case ResolverTypeDOQ:
		return &doqResolver{uc: uc}, nil
	case ResolverTypeOS:
		return &osResolver{}, nil
	case ResolverTypeLegacy:
		return &legacyResolver{endpoint: endpoint}, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnknownResolver, typ)
}

type osResolver struct{}

func (o *osResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	domain := canonicalName(msg.Question[0].Name)
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no answer")
	}
	answer := new(dns.Msg)
	answer.SetReply(msg)
	ip := net.ParseIP(addrs[0])
	a := &dns.A{
		A:   ip,
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
	}
	if ip.To4() != nil {
		a.Hdr.Rrtype = dns.TypeA
	}

	msg.Answer = append(msg.Answer, a)
	return msg, nil
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
	endpoint string
}

func (r *legacyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// See comment in (*dotResolver).resolve method.
	dialer := newDialer(net.JoinHostPort(bootstrapDNS, "53"))
	dnsClient := &dns.Client{
		Net:    "udp",
		Dialer: dialer,
	}
	answer, _, err := dnsClient.ExchangeContext(ctx, msg, r.endpoint)
	return answer, err
}

// canonicalName returns canonical name from FQDN with "." trimmed.
func canonicalName(fqdn string) string {
	q := strings.TrimSpace(fqdn)
	q = strings.TrimSuffix(q, ".")
	// https://datatracker.ietf.org/doc/html/rfc4343
	q = strings.ToLower(q)

	return q
}

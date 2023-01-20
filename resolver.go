package ctrld

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

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
	typ, endpoint := uc.Type, uc.Endpoint
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
		return &legacyResolver{endpoint: endpoint}, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnknownResolver, typ)
}

type osResolver struct {
	nameservers []string
	next        atomic.Uint32
}

// Resolve performs DNS resolvers using OS default nameservers. Nameserver is chosen from
// available nameservers with a roundrobin algorithm.
func (o *osResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	numServers := uint32(len(o.nameservers))
	if numServers == 0 {
		return nil, errors.New("no nameservers available")
	}
	next := o.next.Add(1)
	server := o.nameservers[(next-1)%numServers]
	dnsClient := &dns.Client{Net: "udp"}
	answer, _, err := dnsClient.ExchangeContext(ctx, msg, server)

	return answer, err
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

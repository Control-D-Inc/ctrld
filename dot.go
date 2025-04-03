package ctrld

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

type dotResolver struct {
	uc *UpstreamConfig
}

func (r *dotResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// The dialer is used to prevent bootstrapping cycle.
	// If r.endpoint is set to dns.controld.dev, we need to resolve
	// dns.controld.dev first. By using a dialer with custom resolver,
	// we ensure that we can always resolve the bootstrap domain
	// regardless of the machine DNS status.
	dialer := newDialer(net.JoinHostPort(controldPublicDns, "53"))
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	tcpNet, _ := r.uc.netForDNSType(ctx, dnsTyp)
	dnsClient := &dns.Client{
		Net:       tcpNet,
		Dialer:    dialer,
		TLSConfig: &tls.Config{RootCAs: r.uc.certPool},
	}
	endpoint := r.uc.Endpoint
	if r.uc.BootstrapIP != "" {
		dnsClient.TLSConfig.ServerName = r.uc.Domain
		dnsClient.Net = "tcp-tls"
		_, port, _ := net.SplitHostPort(endpoint)
		endpoint = net.JoinHostPort(r.uc.BootstrapIP, port)
	}

	answer, _, err := dnsClient.ExchangeContext(ctx, msg, endpoint)
	return answer, wrapCertificateVerificationError(err)
}

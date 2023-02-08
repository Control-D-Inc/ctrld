//go:build !qf

package ctrld

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (uc *UpstreamConfig) setupDOH3Transport() {
	rt := &http3.RoundTripper{}
	rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		host := addr
		ProxyLog.Debug().Msgf("debug dial context D0H3 %s - %s", addr, bootstrapDNS)
		// if we have a bootstrap ip set, use it to avoid DNS lookup
		if uc.BootstrapIP != "" {
			if _, port, _ := net.SplitHostPort(addr); port != "" {
				addr = net.JoinHostPort(uc.BootstrapIP, port)
			}
			ProxyLog.Debug().Msgf("sending doh3 request to: %s", addr)
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}

		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return quic.DialEarlyContext(ctx, udpConn, remoteAddr, host, tlsCfg, cfg)
	}

	uc.http3RoundTripper = rt
	uc.pingUpstream()
}

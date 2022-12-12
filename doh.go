package ctrld

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
)

func newDohResolver(uc *UpstreamConfig) *dohResolver {
	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}
		Log(ctx, ProxyLog.Debug(), "debug dial context %s - %s - %s", addr, network, bootstrapDNS)
		// if we have a bootstrap ip set, use it to avoid DNS lookup
		if uc.BootstrapIP != "" && addr == fmt.Sprintf("%s:443", uc.Domain) {
			addr = fmt.Sprintf("%s:443", uc.BootstrapIP)
			Log(ctx, ProxyLog.Debug(), "sending doh request to: %s", addr)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	r := &dohResolver{endpoint: uc.Endpoint, isDoH3: uc.Type == resolverTypeDOH3}
	if r.isDoH3 {
		r.doh3DialFunc = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			host := addr
			Log(ctx, ProxyLog.Debug(), "debug dial context D0H3 %s - %s", addr, bootstrapDNS)
			// if we have a bootstrap ip set, use it to avoid DNS lookup
			if uc.BootstrapIP != "" && addr == fmt.Sprintf("%s:443", uc.Domain) {
				addr = fmt.Sprintf("%s:443", uc.BootstrapIP)
				Log(ctx, ProxyLog.Debug(), "sending doh3 request to: %s", addr)
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				return nil, err
			}
			return quic.DialEarlyContext(ctx, udpConn, remoteAddr, host, tlsCfg, cfg)
		}
	}
	return r
}

type dohResolver struct {
	endpoint     string
	isDoH3       bool
	doh3DialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)
}

func (r *dohResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(data)
	url := fmt.Sprintf("%s?dns=%s", r.endpoint, enc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	c := http.Client{}
	if r.isDoH3 {
		c.Transport = &http3.RoundTripper{}
		c.Transport.(*http3.RoundTripper).Dial = r.doh3DialFunc
		defer c.Transport.(*http3.RoundTripper).Close()
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not perform request: %w", err)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read message from response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong response from DOH server, got: %s, status: %d", string(buf), resp.StatusCode)
	}

	answer := new(dns.Msg)
	return answer, answer.Unpack(buf)
}

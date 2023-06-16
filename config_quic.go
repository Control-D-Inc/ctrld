//go:build !qf

package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

func (uc *UpstreamConfig) setupDOH3Transport() {
	switch uc.IPStack {
	case IpStackBoth, "":
		uc.http3RoundTripper = uc.newDOH3Transport(uc.bootstrapIPs)
	case IpStackV4:
		uc.http3RoundTripper = uc.newDOH3Transport(uc.bootstrapIPs4)
	case IpStackV6:
		uc.http3RoundTripper = uc.newDOH3Transport(uc.bootstrapIPs6)
	case IpStackSplit:
		uc.http3RoundTripper4 = uc.newDOH3Transport(uc.bootstrapIPs4)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if ctrldnet.IPv6Available(ctx) {
			uc.http3RoundTripper6 = uc.newDOH3Transport(uc.bootstrapIPs6)
		} else {
			uc.http3RoundTripper6 = uc.http3RoundTripper4
		}
		uc.http3RoundTripper = uc.newDOH3Transport(uc.bootstrapIPs)
	}
}

func (uc *UpstreamConfig) newDOH3Transport(addrs []string) http.RoundTripper {
	rt := &http3.RoundTripper{}
	rt.TLSClientConfig = &tls.Config{RootCAs: uc.certPool}
	rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		domain := addr
		_, port, _ := net.SplitHostPort(addr)
		// if we have a bootstrap ip set, use it to avoid DNS lookup
		if uc.BootstrapIP != "" {
			addr = net.JoinHostPort(uc.BootstrapIP, port)
			ProxyLog.Debug().Msgf("sending doh3 request to: %s", addr)
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quic.DialEarlyContext(ctx, udpConn, remoteAddr, domain, tlsCfg, cfg)
		}
		dialAddrs := make([]string, len(addrs))
		for i := range addrs {
			dialAddrs[i] = net.JoinHostPort(addrs[i], port)
		}
		pd := &quicParallelDialer{}
		conn, err := pd.Dial(ctx, domain, dialAddrs, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}
		ProxyLog.Debug().Msgf("sending doh3 request to: %s", conn.RemoteAddr())
		return conn, err
	}
	return rt
}

func (uc *UpstreamConfig) doh3Transport(dnsType uint16) http.RoundTripper {
	uc.transportOnce.Do(func() {
		uc.SetupTransport()
	})
	if uc.rebootstrap.CompareAndSwap(true, false) {
		uc.SetupTransport()
	}
	switch uc.IPStack {
	case IpStackBoth, IpStackV4, IpStackV6:
		return uc.http3RoundTripper
	case IpStackSplit:
		switch dnsType {
		case dns.TypeA:
			return uc.http3RoundTripper4
		default:
			return uc.http3RoundTripper6
		}
	}
	return uc.http3RoundTripper
}

// Putting the code for quic parallel dialer here:
//
//   - quic dialer is different with net.Dialer
//   - simplification for quic free version
type parallelDialerResult struct {
	conn quic.EarlyConnection
	err  error
}

type quicParallelDialer struct{}

// Dial performs parallel dialing to the given address list.
func (d *quicParallelDialer) Dial(ctx context.Context, domain string, addrs []string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	if len(addrs) == 0 {
		return nil, errors.New("empty addresses")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan *parallelDialerResult, len(addrs))
	var wg sync.WaitGroup
	wg.Add(len(addrs))
	go func() {
		wg.Wait()
		close(ch)
	}()

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		go func(addr string) {
			defer wg.Done()
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				ch <- &parallelDialerResult{conn: nil, err: err}
				return
			}

			conn, err := quic.DialEarlyContext(ctx, udpConn, remoteAddr, domain, tlsCfg, cfg)
			ch <- &parallelDialerResult{conn: conn, err: err}
		}(addr)
	}

	errs := make([]error, 0, len(addrs))
	for res := range ch {
		if res.err == nil {
			cancel()
			return res.conn, res.err
		}
		errs = append(errs, res.err)
	}

	return nil, errors.Join(errs...)
}

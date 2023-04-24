//go:build !qf

package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (uc *UpstreamConfig) setupDOH3Transport() {
	uc.setupDOH3TransportWithoutPingUpstream()
	uc.pingUpstream()
}

func (uc *UpstreamConfig) setupDOH3TransportWithoutPingUpstream() {
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
		addrs := make([]string, len(uc.bootstrapIPs))
		for i := range uc.bootstrapIPs {
			addrs[i] = net.JoinHostPort(uc.bootstrapIPs[i], port)
		}
		pd := &quicParallelDialer{}
		conn, err := pd.Dial(ctx, domain, addrs, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}
		ProxyLog.Debug().Msgf("sending doh3 request to: %s", conn.RemoteAddr())
		return conn, err
	}

	uc.http3RoundTripper = rt
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

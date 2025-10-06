package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"runtime"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
		if HasIPv6() {
			uc.http3RoundTripper6 = uc.newDOH3Transport(uc.bootstrapIPs6)
		} else {
			uc.http3RoundTripper6 = uc.http3RoundTripper4
		}
		uc.http3RoundTripper = uc.newDOH3Transport(uc.bootstrapIPs)
	}
}

func (uc *UpstreamConfig) newDOH3Transport(addrs []string) http.RoundTripper {
	rt := &http3.Transport{}
	rt.TLSClientConfig = &tls.Config{RootCAs: uc.certPool}
	rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		// if we have a bootstrap ip set, use it to avoid DNS lookup
		if uc.BootstrapIP != "" {
			addr = net.JoinHostPort(uc.BootstrapIP, port)
			ProxyLogger.Load().Debug().Msgf("sending doh3 request to: %s", addr)
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, udpConn, remoteAddr, tlsCfg, cfg)
		}
		dialAddrs := make([]string, len(addrs))
		for i := range addrs {
			dialAddrs[i] = net.JoinHostPort(addrs[i], port)
		}
		pd := &quicParallelDialer{}
		conn, err := pd.Dial(ctx, dialAddrs, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}
		ProxyLogger.Load().Debug().Msgf("sending doh3 request to: %s", conn.RemoteAddr())
		return conn, err
	}
	runtime.SetFinalizer(rt, func(rt *http3.Transport) {
		rt.CloseIdleConnections()
	})
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
	conn *quic.Conn
	err  error
}

type quicParallelDialer struct{}

// Dial performs parallel dialing to the given address list.
func (d *quicParallelDialer) Dial(ctx context.Context, addrs []string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("empty addresses")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	defer close(done)
	ch := make(chan *parallelDialerResult, len(addrs))
	var wg sync.WaitGroup
	wg.Add(len(addrs))
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, addr := range addrs {
		go func(addr string) {
			defer wg.Done()
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				ch <- &parallelDialerResult{conn: nil, err: err}
				return
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				ch <- &parallelDialerResult{conn: nil, err: err}
				return
			}
			conn, err := quic.DialEarly(ctx, udpConn, remoteAddr, tlsCfg, cfg)
			select {
			case ch <- &parallelDialerResult{conn: conn, err: err}:
			case <-done:
				if conn != nil {
					conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
				}
				if udpConn != nil {
					udpConn.Close()
				}
			}
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

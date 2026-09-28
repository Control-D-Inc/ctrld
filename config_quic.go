package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"runtime"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (uc *UpstreamConfig) newDOH3Transport(addrs []string) http.RoundTripper {
	if uc.Type != ResolverTypeDOH3 {
		return nil
	}
	rt := &http3.Transport{}
	rt.TLSClientConfig = &tls.Config{RootCAs: uc.certPool, MinVersion: tls.VersionTLS12}
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
				udpConn.Close()
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, udpConn, remoteAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			closeUDPConnWhenDone(conn, udpConn)
			return conn, nil
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
	uc.ensureSetupTransport()
	return transportByIpStack(uc.IPStack, dnsType, uc.http3RoundTripper, uc.http3RoundTripper4, uc.http3RoundTripper6)
}

func (uc *UpstreamConfig) doqTransport(dnsType uint16) *doqConnPool {
	uc.ensureSetupTransport()
	return transportByIpStack(uc.IPStack, dnsType, uc.doqConnPool, uc.doqConnPool4, uc.doqConnPool6)
}

func (uc *UpstreamConfig) dotTransport(dnsType uint16) *dotConnPool {
	uc.ensureSetupTransport()
	return transportByIpStack(uc.IPStack, dnsType, uc.dotClientPool, uc.dotClientPool4, uc.dotClientPool6)
}

// Putting the code for quic parallel dialer here:
//
//   - quic dialer is different with net.Dialer
//   - simplification for quic free version
type parallelDialerResult struct {
	conn    *quic.Conn
	udpConn *net.UDPConn
	err     error
}

// closeUDPConnWhenDone closes udpConn once conn terminates. quic.DialEarly does
// not take ownership of the socket it is handed, so the caller must.
func closeUDPConnWhenDone(conn *quic.Conn, udpConn *net.UDPConn) {
	go func() {
		<-conn.Context().Done()
		_ = udpConn.Close()
	}()
}

// quicParallelDialer races DialEarly across a list of remote addresses and
// returns the first successful connection. When transport is non-nil, all dials
// share that transport's UDP socket. When transport is nil, the dialer falls
// back to a fresh UDP socket per attempt; losing sockets are closed as their
// dials settle, and the winning one is closed with the connection it carries.
type quicParallelDialer struct {
	transport *quic.Transport
}

// Dial performs parallel dialing to the given address list.
func (d *quicParallelDialer) Dial(ctx context.Context, addrs []string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
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

	for _, addr := range addrs {
		go func(addr string) {
			defer wg.Done()
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				ch <- &parallelDialerResult{conn: nil, err: err}
				return
			}
			var (
				conn    *quic.Conn
				udpConn *net.UDPConn
			)
			if d.transport != nil {
				conn, err = d.transport.DialEarly(ctx, remoteAddr, tlsCfg, cfg)
			} else {
				udpConn, err = net.ListenUDP("udp", nil)
				if err != nil {
					ch <- &parallelDialerResult{conn: nil, err: err}
					return
				}
				conn, err = quic.DialEarly(ctx, udpConn, remoteAddr, tlsCfg, cfg)
				if err != nil {
					udpConn.Close()
					udpConn = nil
				}
			}
			ch <- &parallelDialerResult{conn: conn, udpConn: udpConn, err: err}
		}(addr)
	}

	errs := make([]error, 0, len(addrs))
	for res := range ch {
		if res.err == nil {
			cancel()
			if res.udpConn != nil {
				closeUDPConnWhenDone(res.conn, res.udpConn)
			}
			go closeLosingQuicConns(ch)
			return res.conn, nil
		}
		errs = append(errs, res.err)
	}

	return nil, errors.Join(errs...)
}

// closeLosingQuicConns drains ch and releases everything left in it.
func closeLosingQuicConns(ch <-chan *parallelDialerResult) {
	for res := range ch {
		if res.conn != nil {
			res.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		}
		if res.udpConn != nil {
			_ = res.udpConn.Close()
		}
	}
}

func (uc *UpstreamConfig) newDOQConnPool(addrs []string) *doqConnPool {
	if uc.Type != ResolverTypeDOQ {
		return nil
	}
	return newDOQConnPool(uc, addrs)
}

func (uc *UpstreamConfig) newDOTClientPool(addrs []string) *dotConnPool {
	if uc.Type != ResolverTypeDOT {
		return nil
	}
	return newDOTClientPool(uc, addrs)
}

package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/miekg/dns"
)

type dotResolver struct {
	uc *UpstreamConfig
}

func (r *dotResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if err := validateMsg(msg); err != nil {
		return nil, err
	}
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "DoT resolver query started")

	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}

	pool := r.uc.dotTransport(ctx, dnsTyp)
	if pool == nil {
		Log(ctx, logger.Error(), "DoT client pool is not available")
		return nil, errors.New("DoT client pool is not available")
	}

	answer, err := pool.Resolve(ctx, msg)
	if err != nil {
		Log(ctx, logger.Error().Err(err), "DoT request failed")
	} else {
		Log(ctx, logger.Debug(), "DoT resolver query successful")
	}
	return answer, err
}

const dotPoolSize = 16

// dotConnPool manages a pool of TCP/TLS connections for DoT queries using a buffered channel.
type dotConnPool struct {
	uc        *UpstreamConfig
	addrs     []string
	port      string
	tlsConfig *tls.Config
	dialer    *net.Dialer
	conns     chan *dotConn
}

type dotConn struct {
	conn *tls.Conn
}

func newDOTClientPool(_ context.Context, uc *UpstreamConfig, addrs []string) *dotConnPool {
	_, port, _ := net.SplitHostPort(uc.Endpoint)
	if port == "" {
		port = "853"
	}

	// The dialer is used to prevent bootstrapping cycle.
	// If endpoint is set to dns.controld.dev, we need to resolve
	// dns.controld.dev first. By using a dialer with custom resolver,
	// we ensure that we can always resolve the bootstrap domain
	// regardless of the machine DNS status.
	dialer := newDialer(net.JoinHostPort(controldPublicDns, "53"))

	tlsConfig := &tls.Config{
		RootCAs: uc.certPool,
	}

	if uc.BootstrapIP != "" {
		tlsConfig.ServerName = uc.Domain
	}

	pool := &dotConnPool{
		uc:        uc,
		addrs:     addrs,
		port:      port,
		tlsConfig: tlsConfig,
		dialer:    dialer,
		conns:     make(chan *dotConn, dotPoolSize),
	}

	// Use SetFinalizer here because we need to call a method on the pool itself.
	// AddCleanup would require passing the pool as arg (which panics) or capturing
	// it in a closure (which prevents GC). SetFinalizer is appropriate for this case.
	runtime.SetFinalizer(pool, func(p *dotConnPool) {
		p.CloseIdleConnections()
	})

	return pool
}

// Resolve performs a DNS query using a pooled TCP/TLS connection.
func (p *dotConnPool) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("nil DNS message")
	}

	conn, err := p.getConn(ctx)
	if err != nil {
		return nil, wrapCertificateVerificationError(err)
	}

	client := dns.Client{Net: "tcp-tls"}
	answer, _, err := client.ExchangeWithConnContext(ctx, msg, &dns.Conn{Conn: conn})
	isGood := err == nil
	p.putConn(conn, isGood)

	if err != nil {
		return nil, wrapCertificateVerificationError(err)
	}

	return answer, nil
}

// getConn gets a TCP/TLS connection from the pool or creates a new one.
// A connection is taken from the channel while in use; putConn returns it.
func (p *dotConnPool) getConn(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil && isAlive(dc.conn) {
				return dc.conn, nil
			}
			if dc.conn != nil {
				dc.conn.Close()
			}
		default:
			_, conn, err := p.dialConn(ctx)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
}

// putConn returns a connection to the pool for reuse by other goroutines.
func (p *dotConnPool) putConn(conn net.Conn, isGood bool) {
	if !isGood || conn == nil {
		if conn != nil {
			conn.Close()
		}
		return
	}
	dc := &dotConn{conn: conn.(*tls.Conn)}
	select {
	case p.conns <- dc:
	default:
		// Channel full, close the connection
		dc.conn.Close()
	}
}

// dialConn creates a new TCP/TLS connection.
func (p *dotConnPool) dialConn(ctx context.Context) (string, *tls.Conn, error) {
	logger := LoggerFromCtx(ctx)
	var endpoint string

	if p.uc.BootstrapIP != "" {
		endpoint = net.JoinHostPort(p.uc.BootstrapIP, p.port)
		Log(ctx, logger.Debug(), "Sending DoT request to: %s", endpoint)
		conn, err := p.dialer.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return "", nil, err
		}
		tlsConn := tls.Client(conn, p.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return "", nil, err
		}
		return endpoint, tlsConn, nil
	}

	// Try bootstrap IPs in parallel
	if len(p.addrs) > 0 {
		type result struct {
			conn *tls.Conn
			addr string
			err  error
		}

		ch := make(chan result, len(p.addrs))
		done := make(chan struct{})
		defer close(done)

		for _, addr := range p.addrs {
			go func(addr string) {
				endpoint := net.JoinHostPort(addr, p.port)
				conn, err := p.dialer.DialContext(ctx, "tcp", endpoint)
				if err != nil {
					select {
					case ch <- result{conn: nil, addr: endpoint, err: err}:
					case <-done:
					}
					return
				}
				tlsConfig := p.tlsConfig.Clone()
				tlsConfig.ServerName = p.uc.Domain
				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					conn.Close()
					select {
					case ch <- result{conn: nil, addr: endpoint, err: err}:
					case <-done:
					}
					return
				}
				select {
				case ch <- result{conn: tlsConn, addr: endpoint, err: nil}:
				case <-done:
					if conn != nil {
						conn.Close()
					}
				}
			}(addr)
		}

		errs := make([]error, 0, len(p.addrs))
		for range len(p.addrs) {
			select {
			case res := <-ch:
				if res.err == nil && res.conn != nil {
					Log(ctx, logger.Debug(), "Sending DoT request to: %s", res.addr)
					return res.addr, res.conn, nil
				}
				if res.err != nil {
					errs = append(errs, res.err)
				}
			case <-ctx.Done():
				return "", nil, ctx.Err()
			}
		}

		return "", nil, errors.Join(errs...)
	}

	// Fallback to endpoint resolution
	endpoint = p.uc.Endpoint
	Log(ctx, logger.Debug(), "Sending DoT request to: %s", endpoint)
	conn, err := p.dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return "", nil, err
	}
	tlsConn := tls.Client(conn, p.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return "", nil, err
	}
	return endpoint, tlsConn, nil
}

// CloseIdleConnections closes all connections in the pool.
// Connections currently checked out (in use) are not closed.
func (p *dotConnPool) CloseIdleConnections() {
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil {
				dc.conn.Close()
			}
		default:
			return
		}
	}
}

func isAlive(c *tls.Conn) bool {
	// Set a very short deadline for the read
	c.SetReadDeadline(time.Now().Add(1 * time.Millisecond))

	// Try to read 1 byte without consuming it (using a small buffer)
	one := make([]byte, 1)
	_, err := c.Read(one)

	// Reset the deadline for future operations
	c.SetReadDeadline(time.Time{})

	if err == io.EOF {
		return false // Connection is definitely closed
	}

	// If we get a timeout, it means no data is waiting,
	// but the connection is likely still "up."
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return err == nil
}

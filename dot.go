package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
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

// dotConnPool manages a pool of TCP/TLS connections for DoT queries.
// mu serializes retirement, ownership and idle queue operations.
type dotConnPool struct {
	uc        *UpstreamConfig
	addrs     []string
	port      string
	tlsConfig *tls.Config
	dialer    *net.Dialer
	conns     chan *dotConn

	mu     sync.Mutex
	closed bool
	owned  map[*tls.Conn]struct{} // handshaking, checked-out and idle connections
	ctx    context.Context
	cancel context.CancelFunc
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
		RootCAs:    uc.certPool,
		MinVersion: tls.VersionTLS12,
	}

	if uc.BootstrapIP != "" {
		tlsConfig.ServerName = uc.Domain
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &dotConnPool{
		uc:        uc,
		addrs:     addrs,
		port:      port,
		tlsConfig: tlsConfig,
		dialer:    dialer,
		conns:     make(chan *dotConn, dotPoolSize),
		owned:     make(map[*tls.Conn]struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Use SetFinalizer here because we need to call a method on the pool itself.
	// AddCleanup would require passing the pool as arg (which panics) or capturing
	// it in a closure (which prevents GC). SetFinalizer is appropriate for this case.
	runtime.SetFinalizer(pool, func(p *dotConnPool) {
		p.Close()
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
// Checked-out connections remain owned until putConn discards them or Close runs.
func (p *dotConnPool) getConn(ctx context.Context) (net.Conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		select {
		case dc := <-p.conns:
			p.mu.Unlock()
			if dc.conn != nil && isAlive(dc.conn) {
				return dc.conn, nil
			}
			if dc.conn != nil {
				p.putConn(dc.conn, false)
			}
		default:
			p.mu.Unlock()
			_, conn, err := p.dialConn(ctx)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
}

// putConn cannot repopulate a retired pool, even for a successful late response.
func (p *dotConnPool) putConn(conn net.Conn, isGood bool) {
	if conn == nil {
		return
	}
	dc := &dotConn{conn: conn.(*tls.Conn)}
	p.mu.Lock()
	if isGood && !p.closed {
		select {
		case p.conns <- dc:
			p.mu.Unlock()
			return
		default:
		}
	}
	delete(p.owned, dc.conn)
	p.mu.Unlock()
	_ = dc.conn.Close()
}

// dialConn creates a new TCP/TLS connection. Retirement cancels pending TCP
// dials and handshakes; finishing a parallel race cancels and closes its losers.
func (p *dotConnPool) dialConn(ctx context.Context) (string, *tls.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	defer cancel()
	if p.ctx.Err() != nil {
		return "", nil, net.ErrClosed
	}
	logger := LoggerFromCtx(ctx)
	if p.uc.BootstrapIP != "" {
		endpoint := net.JoinHostPort(p.uc.BootstrapIP, p.port)
		Log(ctx, logger.Debug(), "Sending DoT request to: %s", endpoint)
		conn, err := p.dialTLSConn(ctx, endpoint, p.tlsConfig)
		return endpoint, conn, err
	}
	if len(p.addrs) > 0 {
		type result struct {
			conn *tls.Conn
			addr string
			err  error
		}
		// An unbuffered handoff leaves every losing connection with its dialer.
		ch := make(chan result)
		for _, addr := range p.addrs {
			go func(addr string) {
				endpoint := net.JoinHostPort(addr, p.port)
				tlsConfig := p.tlsConfig.Clone()
				tlsConfig.ServerName = p.uc.Domain
				conn, err := p.dialTLSConn(ctx, endpoint, tlsConfig)
				select {
				case ch <- result{conn: conn, addr: endpoint, err: err}:
				case <-ctx.Done():
					if conn != nil {
						p.putConn(conn, false)
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
	endpoint := p.uc.Endpoint
	Log(ctx, logger.Debug(), "Sending DoT request to: %s", endpoint)
	conn, err := p.dialTLSConn(ctx, endpoint, p.tlsConfig)
	return endpoint, conn, err
}

// Register ownership before the TLS handshake so Close interrupts stalled peers.
// A TCP dial racing retirement cannot publish a socket into the closed pool.
func (p *dotConnPool) dialTLSConn(ctx context.Context, endpoint string, cfg *tls.Config) (*tls.Conn, error) {
	conn, err := p.dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, cfg)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	p.owned[tlsConn] = struct{}{}
	p.mu.Unlock()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.putConn(tlsConn, false)
		return nil, err
	}
	return tlsConn, nil
}

// CloseIdleConnections closes only queued connections. The pool remains usable
// and outstanding queries may return their connections. Replacement uses Close.
func (p *dotConnPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil {
				delete(p.owned, dc.conn)
				dc.conn.Close()
			}
		default:
			return
		}
	}
}

// Close permanently retires this pool. Closing the underlying TCP sockets also
// interrupts TLS reads/writes without waiting to send a close_notify.
// Keep the channel open: outstanding borrowers may still call putConn.
func (p *dotConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.cancel()
	for conn := range p.owned {
		_ = conn.NetConn().Close()
		delete(p.owned, conn)
	}
	for len(p.conns) > 0 {
		<-p.conns
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

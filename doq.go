//go:build !qf

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
	"github.com/quic-go/quic-go"
)

type doqResolver struct {
	uc *UpstreamConfig
}

func (r *doqResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if err := validateMsg(msg); err != nil {
		return nil, err
	}

	// Get the appropriate connection pool based on DNS type and IP stack
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}

	pool := r.uc.doqTransport(dnsTyp)
	if pool == nil {
		return nil, errors.New("DoQ connection pool is not available")
	}

	return pool.Resolve(ctx, msg)
}

// doqConnPool manages a pool of QUIC connections for DoQ queries.
type doqConnPool struct {
	uc        *UpstreamConfig
	addrs     []string
	port      string
	tlsConfig *tls.Config
	mu        sync.RWMutex
	conns     map[string]*doqConn
	closed    bool
}

type doqConn struct {
	conn     *quic.Conn
	lastUsed time.Time
	refCount int
	mu       sync.Mutex
}

func newDOQConnPool(uc *UpstreamConfig, addrs []string) *doqConnPool {
	_, port, _ := net.SplitHostPort(uc.Endpoint)
	if port == "" {
		port = "853"
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"},
		RootCAs:    uc.certPool,
		ServerName: uc.Domain,
	}

	pool := &doqConnPool{
		uc:        uc,
		addrs:     addrs,
		port:      port,
		tlsConfig: tlsConfig,
		conns:     make(map[string]*doqConn),
	}

	// Use SetFinalizer here because we need to call a method on the pool itself.
	// AddCleanup would require passing the pool as arg (which panics) or capturing
	// it in a closure (which prevents GC). SetFinalizer is appropriate for this case.
	runtime.SetFinalizer(pool, func(p *doqConnPool) {
		p.CloseIdleConnections()
	})

	return pool
}

// Resolve performs a DNS query using a pooled QUIC connection.
func (p *doqConnPool) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Retry logic for io.EOF errors (as per original implementation)
	for range 5 {
		answer, err := p.doResolve(ctx, msg)
		if err == io.EOF {
			continue
		}
		if err != nil {
			return nil, wrapCertificateVerificationError(err)
		}
		return answer, nil
	}
	return nil, &quic.ApplicationError{
		ErrorCode:    quic.ApplicationErrorCode(quic.InternalError),
		ErrorMessage: quic.InternalError.Message(),
	}
}

func (p *doqConnPool) doResolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	conn, addr, err := p.getConn(ctx)
	if err != nil {
		return nil, err
	}

	// Pack the DNS message
	msgBytes, err := msg.Pack()
	if err != nil {
		p.putConn(addr, conn, false)
		return nil, err
	}

	// Open a new stream for this query
	stream, err := conn.OpenStream()
	if err != nil {
		p.putConn(addr, conn, false)
		return nil, err
	}

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = stream.SetDeadline(deadline)

	// Write message length (2 bytes) followed by message
	var msgLen = uint16(len(msgBytes))
	var msgLenBytes = []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
	if _, err := stream.Write(msgLenBytes); err != nil {
		stream.Close()
		p.putConn(addr, conn, false)
		return nil, err
	}

	if _, err := stream.Write(msgBytes); err != nil {
		stream.Close()
		p.putConn(addr, conn, false)
		return nil, err
	}

	// Read response
	buf, err := io.ReadAll(stream)
	stream.Close()

	// Return connection to pool (mark as potentially bad if error occurred)
	isGood := err == nil && len(buf) > 0
	p.putConn(addr, conn, isGood)

	if err != nil {
		return nil, err
	}

	// io.ReadAll hides io.EOF error, so check for empty buffer
	if len(buf) == 0 {
		return nil, io.EOF
	}

	// Unpack DNS response (skip 2-byte length prefix)
	answer := new(dns.Msg)
	if err := answer.Unpack(buf[2:]); err != nil {
		return nil, err
	}
	answer.SetReply(msg)
	return answer, nil
}

// getConn gets a QUIC connection from the pool or creates a new one.
func (p *doqConnPool) getConn(ctx context.Context) (*quic.Conn, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, "", io.EOF
	}

	// Try to reuse an existing connection
	for addr, doqConn := range p.conns {
		doqConn.mu.Lock()
		if doqConn.refCount == 0 && doqConn.conn != nil {
			// Check if connection is still alive
			select {
			case <-doqConn.conn.Context().Done():
				// Connection is closed, remove it
				doqConn.mu.Unlock()
				delete(p.conns, addr)
				continue
			default:
			}

			doqConn.refCount++
			doqConn.lastUsed = time.Now()
			conn := doqConn.conn
			doqConn.mu.Unlock()
			return conn, addr, nil
		}
		doqConn.mu.Unlock()
	}

	// No available connection, create a new one
	addr, conn, err := p.dialConn(ctx)
	if err != nil {
		return nil, "", err
	}

	doqConn := &doqConn{
		conn:     conn,
		lastUsed: time.Now(),
		refCount: 1,
	}
	p.conns[addr] = doqConn

	return conn, addr, nil
}

// putConn returns a connection to the pool.
func (p *doqConnPool) putConn(addr string, conn *quic.Conn, isGood bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	doqConn, ok := p.conns[addr]
	if !ok {
		return
	}

	doqConn.mu.Lock()
	defer doqConn.mu.Unlock()

	doqConn.refCount--
	if doqConn.refCount < 0 {
		doqConn.refCount = 0
	}

	// If connection is bad or closed, remove it from pool
	if !isGood || conn.Context().Err() != nil {
		delete(p.conns, addr)
		conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		return
	}

	doqConn.lastUsed = time.Now()
}

// dialConn creates a new QUIC connection using parallel dialing like DoH3.
func (p *doqConnPool) dialConn(ctx context.Context) (string, *quic.Conn, error) {
	logger := ProxyLogger.Load()

	// If we have a bootstrap IP, use it directly
	if p.uc.BootstrapIP != "" {
		addr := net.JoinHostPort(p.uc.BootstrapIP, p.port)
		Log(ctx, logger.Debug(), "Sending DoQ request to: %s", addr)
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return "", nil, err
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			udpConn.Close()
			return "", nil, err
		}
		conn, err := quic.DialEarly(ctx, udpConn, remoteAddr, p.tlsConfig, nil)
		if err != nil {
			udpConn.Close()
			return "", nil, err
		}
		return addr, conn, nil
	}

	// Use parallel dialing like DoH3
	dialAddrs := make([]string, len(p.addrs))
	for i := range p.addrs {
		dialAddrs[i] = net.JoinHostPort(p.addrs[i], p.port)
	}

	pd := &quicParallelDialer{}
	conn, err := pd.Dial(ctx, dialAddrs, p.tlsConfig, nil)
	if err != nil {
		return "", nil, err
	}

	addr := conn.RemoteAddr().String()
	Log(ctx, logger.Debug(), "Sending DoQ request to: %s", addr)
	return addr, conn, nil
}

// CloseIdleConnections closes all idle connections in the pool.
// When called during cleanup (e.g., from finalizer), it closes all connections
// regardless of refCount to prevent resource leaks.
func (p *doqConnPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true

	for addr, dc := range p.conns {
		dc.mu.Lock()
		if dc.conn != nil {
			// Close all connections to ensure proper cleanup, even if in use
			// This prevents resource leaks when the pool is being destroyed
			dc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		}
		dc.mu.Unlock()
		delete(p.conns, addr)
	}
}

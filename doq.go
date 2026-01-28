//go:build !qf

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
	"github.com/quic-go/quic-go"
)

type doqResolver struct {
	uc *UpstreamConfig
}

func (r *doqResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if err := validateMsg(msg); err != nil {
		return nil, err
	}
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "DoQ resolver query started")

	// Get the appropriate connection pool based on DNS type and IP stack
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}

	pool := r.uc.doqTransport(ctx, dnsTyp)
	if pool == nil {
		Log(ctx, logger.Error(), "DoQ connection pool is not available")
		return nil, errors.New("DoQ connection pool is not available")
	}

	answer, err := pool.Resolve(ctx, msg)
	if err != nil {
		Log(ctx, logger.Error().Err(err), "DoQ request failed")
	} else {
		Log(ctx, logger.Debug(), "DoQ resolver query successful")
	}
	return answer, err
}

const doqPoolSize = 16

// doqConnPool manages a pool of QUIC connections for DoQ queries using a buffered channel.
type doqConnPool struct {
	uc        *UpstreamConfig
	addrs     []string
	port      string
	tlsConfig *tls.Config
	conns     chan *doqConn
}

type doqConn struct {
	conn *quic.Conn
}

func newDOQConnPool(_ context.Context, uc *UpstreamConfig, addrs []string) *doqConnPool {
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
		conns:     make(chan *doqConn, doqPoolSize),
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
	conn, err := p.getConn(ctx)
	if err != nil {
		return nil, err
	}

	// Pack the DNS message
	msgBytes, err := msg.Pack()
	if err != nil {
		p.putConn(conn, false)
		return nil, err
	}

	// Open a new stream for this query
	stream, err := conn.OpenStream()
	if err != nil {
		p.putConn(conn, false)
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
		p.putConn(conn, false)
		return nil, err
	}

	if _, err := stream.Write(msgBytes); err != nil {
		stream.Close()
		p.putConn(conn, false)
		return nil, err
	}

	// Read response
	buf, err := io.ReadAll(stream)
	stream.Close()

	// Return connection to pool (mark as potentially bad if error occurred)
	isGood := err == nil && len(buf) > 0
	p.putConn(conn, isGood)

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
// A connection is taken from the channel while in use; putConn returns it.
func (p *doqConnPool) getConn(ctx context.Context) (*quic.Conn, error) {
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil && dc.conn.Context().Err() == nil {
				return dc.conn, nil
			}
			if dc.conn != nil {
				dc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
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
func (p *doqConnPool) putConn(conn *quic.Conn, isGood bool) {
	if !isGood || conn == nil || conn.Context().Err() != nil {
		if conn != nil {
			conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		}
		return
	}
	dc := &doqConn{conn: conn}
	select {
	case p.conns <- dc:
	default:
		// Channel full, close the connection
		dc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	}
}

// dialConn creates a new QUIC connection using parallel dialing like DoH3.
func (p *doqConnPool) dialConn(ctx context.Context) (string, *quic.Conn, error) {
	logger := LoggerFromCtx(ctx)

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

// CloseIdleConnections closes all connections in the pool.
// Connections currently checked out (in use) are not closed.
func (p *doqConnPool) CloseIdleConnections() {
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil {
				dc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
			}
		default:
			return
		}
	}
}

//go:build !qf

package ctrld

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
// A single quic.Transport (and its UDP socket) is shared by every connection in the pool,
// so the OS socket lifecycle is tied to the pool rather than to each dial. Without this
// ownership model, a strict DoQ upstream that triggers reconnect churn would leak one
// caller-owned UDP socket per dial — see github.com/Control-D-Inc/ctrld/issues/309.
type doqConnPool struct {
	uc         *UpstreamConfig
	addrs      []string
	port       string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	conns      chan *doqConn

	transportMu   sync.Mutex
	transport     *quic.Transport
	transportConn *net.UDPConn
	transportErr  error
	transportInit bool
	closed        bool
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
		MinVersion: tls.VersionTLS12,
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
	}

	pool := &doqConnPool{
		uc:         uc,
		addrs:      addrs,
		port:       port,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		conns:      make(chan *doqConn, doqPoolSize),
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
	// Retry logic for transient errors: io.EOF (connection reset),
	// IdleTimeoutError (stale pooled connection timed out), and
	// StreamLimitReachedError (stream credit exhausted before server MAX_STREAMS arrived).
	for range 5 {
		answer, err := p.doResolve(ctx, msg)
		if err == io.EOF {
			continue
		}
		var idleErr *quic.IdleTimeoutError
		if errors.As(err, &idleErr) {
			continue
		}
		var streamLimitErr quic.StreamLimitReachedError
		if errors.As(err, &streamLimitErr) {
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

	// Ensure the context has a deadline before calling OpenStreamSync, which
	// blocks until the server sends a MAX_STREAMS update. Without a deadline the
	// call could block indefinitely when the server never sends the update.
	deadline, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		deadline, _ = ctx.Deadline()
	}

	// OpenStreamSync blocks until the server's MAX_STREAMS credit arrives,
	// avoiding the StreamLimitReachedError race that OpenStream (non-blocking)
	// triggers when the credit replenishment frame is still in flight.
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		p.putConn(conn, false)
		return nil, err
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

	// RFC 9250 section 4.2 requires the client to indicate end-of-request by
	// closing the send side of the stream (STREAM FIN). Servers may defer
	// processing until FIN arrives, so the close must happen before reading.
	// Stream.Close closes only the send direction; the receive direction
	// remains open for the response.
	if err := stream.Close(); err != nil {
		p.putConn(conn, false)
		return nil, err
	}

	buf, err := io.ReadAll(stream)
	if err != nil {
		p.putConn(conn, false)
		return nil, err
	}

	// io.ReadAll hides io.EOF error, so check for empty buffer.
	if len(buf) == 0 {
		p.putConn(conn, false)
		return nil, io.EOF
	}

	// RFC 9250: each DoQ DNS message is encoded as a 2-octet length field
	// followed by the DNS message. Reject responses that are shorter than
	// the prefix or whose prefix declares more bytes than were received,
	// and retire the misbehaving connection. Without this guard, buf[2:]
	// would panic when len(buf) < 2.
	if len(buf) < 2 {
		p.putConn(conn, false)
		return nil, fmt.Errorf("malformed DoQ response: %d byte(s), need >= 2 for length prefix", len(buf))
	}
	respLen := int(buf[0])<<8 | int(buf[1])
	if 2+respLen > len(buf) {
		p.putConn(conn, false)
		return nil, fmt.Errorf("malformed DoQ response: length prefix %d exceeds payload %d", respLen, len(buf)-2)
	}

	p.putConn(conn, true)

	// Unpack DNS response (skip 2-byte length prefix).
	answer := new(dns.Msg)
	if err := answer.Unpack(buf[2 : 2+respLen]); err != nil {
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
// All connections from the pool multiplex on a single pool-owned UDP socket,
// so reconnect churn cannot grow the host's FD count.
func (p *doqConnPool) dialConn(ctx context.Context) (string, *quic.Conn, error) {
	logger := LoggerFromCtx(ctx)

	tr, err := p.getOrInitTransport()
	if err != nil {
		return "", nil, err
	}

	// If we have a bootstrap IP, use it directly
	if p.uc.BootstrapIP != "" {
		addr := net.JoinHostPort(p.uc.BootstrapIP, p.port)
		Log(ctx, logger.Debug(), "Sending DoQ request to: %s", addr)
		remoteAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return "", nil, err
		}
		conn, err := tr.DialEarly(ctx, remoteAddr, p.tlsConfig, p.quicConfig)
		if err != nil {
			return "", nil, err
		}
		return addr, conn, nil
	}

	// Use parallel dialing like DoH3
	dialAddrs := make([]string, len(p.addrs))
	for i := range p.addrs {
		dialAddrs[i] = net.JoinHostPort(p.addrs[i], p.port)
	}

	pd := &quicParallelDialer{transport: tr}
	conn, err := pd.Dial(ctx, dialAddrs, p.tlsConfig, p.quicConfig)
	if err != nil {
		return "", nil, err
	}

	addr := conn.RemoteAddr().String()
	Log(ctx, logger.Debug(), "Sending DoQ request to: %s", addr)
	return addr, conn, nil
}

// getOrInitTransport returns the pool's shared quic.Transport, initialising it
// on first call. Once the pool has been closed it permanently returns an error
// so that callers cannot resurrect a dead pool.
func (p *doqConnPool) getOrInitTransport() (*quic.Transport, error) {
	p.transportMu.Lock()
	defer p.transportMu.Unlock()
	if p.closed {
		return nil, errors.New("doq pool closed")
	}
	if p.transportInit {
		return p.transport, p.transportErr
	}
	p.transportInit = true
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		p.transportErr = err
		return nil, err
	}
	p.transportConn = udpConn
	p.transport = &quic.Transport{Conn: udpConn}
	return p.transport, nil
}

// CloseIdleConnections closes all idle connections, the shared quic.Transport,
// and the pool's UDP socket. Connections currently checked out (in use) get
// terminated by the transport close as well — without that, the OS socket
// would remain bound to a goroutine that the caller cannot reach to clean up.
func (p *doqConnPool) CloseIdleConnections() {
drain:
	for {
		select {
		case dc := <-p.conns:
			if dc.conn != nil {
				dc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
			}
		default:
			break drain
		}
	}
	p.transportMu.Lock()
	if p.closed {
		p.transportMu.Unlock()
		return
	}
	p.closed = true
	tr := p.transport
	udpConn := p.transportConn
	p.transportMu.Unlock()
	if tr != nil {
		_ = tr.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

package ctrld

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// testCertificate represents a test certificate with its components
type testCertificate struct {
	cert     *x509.Certificate
	tlsCert  tls.Certificate
	template *x509.Certificate
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) *testCertificate {
	t.Helper()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test CA",
		},
		Issuer: pkix.Name{
			Organization: []string{"Test Issuer Org"},
			CommonName:   "Test Issuer CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}

	return &testCertificate{
		cert:     cert,
		tlsCert:  tlsCert,
		template: template,
	}
}

// testQUICServer is a structure representing a test QUIC server for handling connections and streams.
// listener is the QUIC listener used to accept incoming connections.
// cert is the x509 certificate used by the server for authentication.
// addr is the address on which the test server is running.
type testQUICServer struct {
	listener *quic.Listener
	cert     *x509.Certificate
	addr     string
}

// newTestQUICServer creates and initializes a test QUIC server with TLS configuration and starts accepting connections.
func newTestQUICServer(t *testing.T) *testQUICServer {
	t.Helper()

	testCert := generateTestCertificate(t)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS12,
	}

	// Create QUIC listener
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatalf("failed to create QUIC listener: %v", err)
	}

	server := &testQUICServer{
		listener: listener,
		cert:     testCert.cert,
		addr:     listener.Addr().String(),
	}

	// Start handling connections
	go server.serve(t)

	// Add cleanup
	t.Cleanup(func() {
		listener.Close()
	})

	return server
}

// serve handles incoming connections on the QUIC listener and delegates them to connection handlers in separate goroutines.
func (s *testQUICServer) serve(t *testing.T) {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			// Check if the error is due to the listener being closed
			if strings.Contains(err.Error(), "server closed") {
				return
			}
			t.Logf("failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(t, conn)
	}
}

// handleConnection manages an individual QUIC connection by accepting and handling incoming streams in separate goroutines.
func (s *testQUICServer) handleConnection(t *testing.T, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go s.handleStream(t, stream)
	}
}

// handleStream processes a single QUIC stream, reads DNS messages, generates a response, and sends it back to the client.
func (s *testQUICServer) handleStream(t *testing.T, stream *quic.Stream) {
	defer stream.Close()

	// Read length (2 bytes)
	lenBuf := make([]byte, 2)
	_, err := stream.Read(lenBuf)
	if err != nil {
		t.Logf("failed to read message length: %v", err)
		return
	}
	msgLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])

	// Read message
	msgBuf := make([]byte, msgLen)
	_, err = stream.Read(msgBuf)
	if err != nil {
		t.Logf("failed to read message: %v", err)
		return
	}

	// Parse DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		t.Logf("failed to unpack DNS message: %v", err)
		return
	}

	// Create response
	response := new(dns.Msg)
	response.SetReply(msg)
	response.Authoritative = true

	// Add a test answer
	if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeA {
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"), // TEST-NET-1 address
		})
	}

	// Pack response
	respBytes, err := response.Pack()
	if err != nil {
		t.Logf("failed to pack response: %v", err)
		return
	}

	// Write length
	respLen := uint16(len(respBytes))
	_, err = stream.Write([]byte{byte(respLen >> 8), byte(respLen & 0xFF)})
	if err != nil {
		t.Logf("failed to write response length: %v", err)
		return
	}

	// Write response
	_, err = stream.Write(respBytes)
	if err != nil {
		t.Logf("failed to write response: %v", err)
		return
	}
}

// malformedDoQServer is a test QUIC server that drains the client's DoQ
// request and writes caller-supplied raw bytes back. The bytes are not
// required to be a well-framed DoQ response, which is what lets the
// regression tests exercise malformed-response handling.
type malformedDoQServer struct {
	listener *quic.Listener
	cert     *x509.Certificate
	addr     string
	response []byte
}

func newMalformedDoQServer(t *testing.T, response []byte) *malformedDoQServer {
	t.Helper()

	testCert := generateTestCertificate(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"doq"},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatalf("failed to create QUIC listener: %v", err)
	}

	s := &malformedDoQServer{
		listener: listener,
		cert:     testCert.cert,
		addr:     listener.Addr().String(),
		response: response,
	}

	go s.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return s
}

func (s *malformedDoQServer) serve() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *malformedDoQServer) handleConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

func (s *malformedDoQServer) handleStream(stream *quic.Stream) {
	defer stream.Close()

	// Drain the client's DoQ-framed request so the client's writes complete
	// cleanly before we reply with our attacker-controlled bytes. Using
	// io.ReadFull because a single Read on a QUIC stream may return short.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	msgLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
	if msgLen > 0 {
		discard := make([]byte, msgLen)
		if _, err := io.ReadFull(stream, discard); err != nil {
			return
		}
	}

	if len(s.response) > 0 {
		_, _ = stream.Write(s.response)
	}
}

// newMalformedDoQUpstream builds an UpstreamConfig wired to a local
// malformed test server with the test certificate trusted via a custom
// cert pool. We bypass SetupBootstrapIP by setting BootstrapIP directly,
// so the pool dials 127.0.0.1 without any DNS lookup.
func newMalformedDoQUpstream(t *testing.T, cert *x509.Certificate, addr string) *UpstreamConfig {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port %q: %v", addr, err)
	}

	uc := &UpstreamConfig{
		Name:        "doq-malformed",
		Type:        ResolverTypeDOQ,
		Endpoint:    addr,
		Domain:      host,
		BootstrapIP: host,
		Timeout:     2000,
	}
	uc.SetCertPool(pool)
	return uc
}

// TestDoQResolve_MalformedResponse verifies that DoQ upstream
// responses violating RFC 9250 framing — fewer than 2 bytes, or a
// length prefix declaring more payload than was received — return a
// handled error instead of panicking on the length-prefix slice.
func TestDoQResolve_MalformedResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		// Empty stream is already handled via io.EOF; locked in so a
		// future change that drops that branch is caught.
		{"empty response", nil},

		// One byte: too short to hold the 2-octet length prefix.
		{"single byte response", []byte{0x00}},

		// Length prefix declares 16 bytes; payload is absent.
		{"length prefix only", []byte{0x00, 0x10}},

		// Length prefix declares 65535 bytes; only 1 byte of payload
		// arrived.
		{"length prefix larger than payload", []byte{0xFF, 0xFF, 0x00}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := newMalformedDoQServer(t, tt.response)
			uc := newMalformedDoQUpstream(t, server.cert, server.addr)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			pool := newDOQConnPool(ctx, uc, []string{"127.0.0.1"})
			t.Cleanup(pool.CloseIdleConnections)

			msg := new(dns.Msg)
			msg.SetQuestion("example.com.", dns.TypeA)
			msg.RecursionDesired = true

			answer, err := pool.Resolve(ctx, msg)
			if err == nil {
				t.Fatalf("Resolve unexpectedly succeeded for malformed response %v; answer=%v", tt.response, answer)
			}
			if answer != nil {
				t.Fatalf("Resolve returned non-nil answer alongside error: answer=%v err=%v", answer, err)
			}
		})
	}
}

// strictDoQServer accepts DoQ queries but defers the response until the
// client signals end-of-request with STREAM FIN, as required by RFC 9250
// section 4.2. It exists to lock in the fix for
// github.com/Control-D-Inc/ctrld/issues/309 where a client
// that never closes its send side caused the server to wait forever and the
// client to churn through reconnects.
type strictDoQServer struct {
	listener *quic.Listener
	cert     *x509.Certificate
	addr     string
}

func newStrictDoQServer(t *testing.T) *strictDoQServer {
	t.Helper()

	testCert := generateTestCertificate(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatalf("failed to create QUIC listener: %v", err)
	}

	s := &strictDoQServer{
		listener: listener,
		cert:     testCert.cert,
		addr:     listener.Addr().String(),
	}
	go s.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return s
}

func (s *strictDoQServer) serve() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *strictDoQServer) handleConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

func (s *strictDoQServer) handleStream(stream *quic.Stream) {
	defer stream.Close()

	// Drain until the client closes the send side. This is the behaviour
	// that triggered the bug: if the client never sends STREAM FIN, this
	// read blocks until the stream's deadline fires.
	body, err := io.ReadAll(stream)
	if err != nil {
		return
	}
	if len(body) < 2 {
		return
	}
	msgLen := uint16(body[0])<<8 | uint16(body[1])
	if int(msgLen) != len(body)-2 {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body[2:]); err != nil {
		return
	}

	response := new(dns.Msg)
	response.SetReply(msg)
	response.Authoritative = true
	if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeA {
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"),
		})
	}

	respBytes, err := response.Pack()
	if err != nil {
		return
	}
	respLen := uint16(len(respBytes))
	if _, err := stream.Write([]byte{byte(respLen >> 8), byte(respLen & 0xFF)}); err != nil {
		return
	}
	if _, err := stream.Write(respBytes); err != nil {
		return
	}
}

func newStrictDoQUpstream(t *testing.T, cert *x509.Certificate, addr string, useBootstrap bool) *UpstreamConfig {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port %q: %v", addr, err)
	}

	uc := &UpstreamConfig{
		Name:     "doq-strict",
		Type:     ResolverTypeDOQ,
		Endpoint: addr,
		Domain:   host,
		Timeout:  3000,
	}
	if useBootstrap {
		uc.BootstrapIP = host
	}
	uc.SetCertPool(pool)
	return uc
}

// TestDoQResolve_StrictServerWaitsForFIN exercises the RFC 9250 client-FIN
// requirement. With the bug present, the server's io.ReadAll blocks until
// the stream deadline expires and the client sees a timeout, so a successful
// resolve here proves that the client now sends STREAM FIN before reading.
func TestDoQResolve_StrictServerWaitsForFIN(t *testing.T) {
	t.Parallel()

	server := newStrictDoQServer(t)
	uc := newStrictDoQUpstream(t, server.cert, server.addr, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, _, _ := net.SplitHostPort(server.addr)
	pool := newDOQConnPool(ctx, uc, []string{host})
	t.Cleanup(pool.CloseIdleConnections)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	answer, err := pool.Resolve(ctx, msg)
	if err != nil {
		t.Fatalf("Resolve failed against strict DoQ server: %v", err)
	}
	if answer == nil || len(answer.Answer) == 0 {
		t.Fatalf("Resolve returned no answer records: %+v", answer)
	}
	a, ok := answer.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("unexpected answer: %+v", answer.Answer[0])
	}
}

// TestDoQResolve_ParallelDialPathStrictFIN exercises the parallel-dial path
// (no BootstrapIP) against the same FIN-strict server, so that both the
// single-dial branch and the parallel-dial branch are covered.
func TestDoQResolve_ParallelDialPathStrictFIN(t *testing.T) {
	t.Parallel()

	server := newStrictDoQServer(t)
	uc := newStrictDoQUpstream(t, server.cert, server.addr, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, _, _ := net.SplitHostPort(server.addr)
	pool := newDOQConnPool(ctx, uc, []string{host})
	t.Cleanup(pool.CloseIdleConnections)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	answer, err := pool.Resolve(ctx, msg)
	if err != nil {
		t.Fatalf("Resolve (parallel-dial path) failed against strict DoQ server: %v", err)
	}
	if answer == nil || len(answer.Answer) == 0 {
		t.Fatalf("Resolve (parallel-dial path) returned no answer records: %+v", answer)
	}
}

// TestDoQPool_ChurnDoesNotGrowFDs exercises the reconnect-churn scenario
// described in github.com/Control-D-Inc/ctrld/issues/309: repeated dials
// against a server that closes existing connections must not grow the process
// FD count, because the pool now shares one UDP socket via quic.Transport instead
// of allocating one per dial. Linux-only because /proc/self/fd is the cheapest
// portable proxy for "what's still open."
func TestDoQPool_ChurnDoesNotGrowFDs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("FD accounting via /proc/self/fd is linux-only")
	}
	t.Parallel()

	server := newStrictDoQServer(t)
	uc := newStrictDoQUpstream(t, server.cert, server.addr, true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	host, _, _ := net.SplitHostPort(server.addr)
	pool := newDOQConnPool(ctx, uc, []string{host})
	t.Cleanup(pool.CloseIdleConnections)

	makeQuery := func(i int) *dns.Msg {
		msg := new(dns.Msg)
		// Vary the question so any caching layer cannot short-circuit.
		msg.SetQuestion(dns.Fqdn(strings.Repeat("a", 1+i%8)+".example.com"), dns.TypeA)
		msg.RecursionDesired = true
		return msg
	}

	// Warm the pool so the steady-state transport and at least one
	// connection are open. Without this, the first resolve in the measured
	// loop would inflate the baseline.
	if _, err := pool.Resolve(ctx, makeQuery(0)); err != nil {
		t.Fatalf("warm-up Resolve failed: %v", err)
	}

	baseline := countOpenFDs(t)

	// Force reconnect churn by closing the connection between each query.
	// Without the fix this would leak one UDP socket per round; with the
	// fix the pool's shared transport keeps a single socket open.
	const rounds = 20
	for i := 1; i <= rounds; i++ {
		// Drain any pooled connection so the next Resolve has to redial.
		drainPooledConns(pool)

		if _, err := pool.Resolve(ctx, makeQuery(i)); err != nil {
			t.Fatalf("Resolve in churn loop iteration %d failed: %v", i, err)
		}
	}

	// Give quic-go a moment to drop any background goroutines that hold
	// references to closed sockets.
	time.Sleep(200 * time.Millisecond)

	after := countOpenFDs(t)

	// Allow a small slack for transient FDs (goroutine wake-ups, qlog,
	// etc.) but reject anything that scales with the number of rounds.
	const slack = 5
	if after > baseline+slack {
		t.Fatalf("FD count grew under DoQ churn: baseline=%d after=%d rounds=%d (slack=%d)", baseline, after, rounds, slack)
	}
}

// drainPooledConns removes any idle pooled connections so the next Resolve
// is forced to dial a fresh one. It does not close the pool's transport.
func drainPooledConns(p *doqConnPool) {
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

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

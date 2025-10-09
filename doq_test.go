// test_helpers.go
package ctrld

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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
func (s *testQUICServer) handleConnection(t *testing.T, conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go s.handleStream(t, stream)
	}
}

// handleStream processes a single QUIC stream, reads DNS messages, generates a response, and sends it back to the client.
func (s *testQUICServer) handleStream(t *testing.T, stream quic.Stream) {
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

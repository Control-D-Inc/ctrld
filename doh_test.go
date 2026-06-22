package ctrld

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

func Test_dohOsHeaderValue(t *testing.T) {
	val := dohOsHeaderValue
	if val == "" {
		t.Fatalf("empty %s", dohOsHeader)
	}
	t.Log(val)

	encodedOs := EncodeOsNameMap[runtime.GOOS]
	if encodedOs == "" {
		t.Fatalf("missing encoding value for: %q", runtime.GOOS)
	}
	decodedOs := DecodeOsNameMap[encodedOs]
	if decodedOs == "" {
		t.Fatalf("missing decoding value for: %q", runtime.GOOS)
	}
}

func Test_wrapUrlError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr string
	}{
		{
			name:    "No wrapping for non-URL errors",
			err:     errors.New("plain error"),
			wantErr: "plain error",
		},
		{
			name: "URL error without TLS error",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com",
				Err: errors.New("underlying error"),
			},
			wantErr: "Get \"https://example.com\": underlying error",
		},
		{
			name: "TLS error with missing unverified certificate data",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com",
				Err: &tls.CertificateVerificationError{
					UnverifiedCertificates: nil,
					Err:                    &x509.UnknownAuthorityError{},
				},
			},
			wantErr: `Get "https://example.com": tls: failed to verify certificate: x509: certificate signed by unknown authority`,
		},
		{
			name: "TLS error with valid certificate data",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com",
				Err: &tls.CertificateVerificationError{
					UnverifiedCertificates: []*x509.Certificate{
						{
							Subject: pkix.Name{
								CommonName:   "BadSubjectCN",
								Organization: []string{"BadSubjectOrg"},
							},
							Issuer: pkix.Name{
								CommonName:   "BadIssuerCN",
								Organization: []string{"BadIssuerOrg"},
							},
						},
					},
					Err: &x509.UnknownAuthorityError{},
				},
			},
			wantErr: `Get "https://example.com": tls: failed to verify certificate: x509: certificate signed by unknown authority: BadSubjectCN, BadSubjectOrg, BadIssuerOrg`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := wrapUrlError(tt.err)
			if gotErr.Error() != tt.wantErr {
				t.Errorf("wrapCertificateVerificationError() error = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}

func Test_ClientCertificateVerificationError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
	})
	tlsServer, cert := testTLSServer(t, handler)
	tlsServerUrl, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	quicServer := newTestQUICServer(t)
	http3Server := newTestHTTP3Server(t, handler)

	tests := []struct {
		name string
		uc   *UpstreamConfig
	}{
		{
			"doh",
			&UpstreamConfig{
				Name:     "doh",
				Type:     ResolverTypeDOH,
				Endpoint: tlsServer.URL,
				Timeout:  1000,
			},
		},
		{
			"doh3",
			&UpstreamConfig{
				Name:     "doh3",
				Type:     ResolverTypeDOH3,
				Endpoint: http3Server.addr,
				Timeout:  5000,
			},
		},
		{
			"doq",
			&UpstreamConfig{
				Name:     "doq",
				Type:     ResolverTypeDOQ,
				Endpoint: quicServer.addr,
				Timeout:  5000,
			},
		},
		{
			"dot",
			&UpstreamConfig{
				Name:     "dot",
				Type:     ResolverTypeDOT,
				Endpoint: net.JoinHostPort(tlsServerUrl.Hostname(), tlsServerUrl.Port()),
				Timeout:  1000,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.uc.Init()
			tc.uc.SetupBootstrapIP()
			r, err := NewResolver(tc.uc)
			if err != nil {
				t.Fatal(err)
			}
			msg := new(dns.Msg)
			msg.SetQuestion("verify.controld.com.", dns.TypeA)
			msg.RecursionDesired = true
			_, err = r.Resolve(context.Background(), msg)
			// Verify the error contains the expected certificate information
			if err == nil {
				t.Fatal("expected certificate verification error, got nil")
			}

			// You can check the error contains information about the test certificate
			if !strings.Contains(err.Error(), cert.Issuer.CommonName) {
				t.Fatalf("error should contain issuer information %q, got: %v", cert.Issuer.CommonName, err)
			}
		})
	}
}

// testTLSServer creates an HTTPS test server with a self-signed certificate
// returns the server and its certificate for verification testing
// testTLSServer creates an HTTPS test server with a self-signed certificate
func testTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.Certificate) {
	t.Helper()

	testCert := generateTestCertificate(t)

	// Create a test server
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()

	// Add cleanup
	t.Cleanup(server.Close)

	return server, testCert.cert
}

// testHTTP3Server represents a structure for an HTTP/3 test server with its server instance, TLS certificate, and address.
type testHTTP3Server struct {
	server *http3.Server
	cert   *x509.Certificate
	addr   string
}

// newTestHTTP3Server creates and starts a test HTTP/3 server with a given handler and returns the server instance.
func newTestHTTP3Server(t *testing.T, handler http.Handler) *testHTTP3Server {
	t.Helper()

	testCert := generateTestCertificate(t)

	// First create a listener to get the actual port
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}

	// Get the actual address
	actualAddr := udpConn.LocalAddr().String()

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"h3"}, // HTTP/3 protocol identifier
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP/3 server
	server := &http3.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	// Start the server with the existing UDP connection
	go func() {
		if err := server.Serve(udpConn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("HTTP/3 server error: %v", err)
		}
	}()

	h3Server := &testHTTP3Server{
		server: server,
		cert:   testCert.cert,
		addr:   actualAddr,
	}

	// Add cleanup
	t.Cleanup(func() {
		server.Close()
		udpConn.Close()
	})

	// Wait a bit for the server to be ready
	time.Sleep(100 * time.Millisecond)

	return h3Server
}

// oversizedDoHHandler streams `bodyBytes` bytes of zeros with the given
// HTTP status. The atomic counter records bytes the handler actually
// wrote, so tests can confirm the client tore down the stream before
// consuming the whole attacker-controlled body.
func oversizedDoHHandler(status int, bodyBytes int64, written *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", headerApplicationDNS)
		w.WriteHeader(status)
		chunk := make([]byte, 64*1024)
		var sent int64
		for sent < bodyBytes {
			n := int64(len(chunk))
			if remaining := bodyBytes - sent; remaining < n {
				n = remaining
			}
			m, err := w.Write(chunk[:n])
			if err != nil {
				return
			}
			sent += int64(m)
			if written != nil {
				written.Add(int64(m))
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

// dohUpstreamForTLSServer wires an UpstreamConfig at a local httptest TLS
// server, trusting its self-signed certificate. BootstrapIP is set so no
// real DNS lookup runs.
func dohUpstreamForTLSServer(t *testing.T, srv *httptest.Server) *UpstreamConfig {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	uc := &UpstreamConfig{
		Name:        "doh-oversize",
		Type:        ResolverTypeDOH,
		Endpoint:    srv.URL + "/dns-query",
		BootstrapIP: u.Hostname(),
		Timeout:     2000,
	}
	uc.SetCertPool(pool)
	uc.Init()
	return uc
}

// doh3UpstreamForAddr wires an UpstreamConfig at a local HTTP/3 server,
// trusting its self-signed certificate.
func doh3UpstreamForAddr(t *testing.T, addr string, cert *x509.Certificate) *UpstreamConfig {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port %q: %v", addr, err)
	}
	uc := &UpstreamConfig{
		Name:        "doh3-oversize",
		Type:        ResolverTypeDOH3,
		Endpoint:    "h3://" + addr + "/dns-query",
		BootstrapIP: host,
		Timeout:     5000,
	}
	uc.SetCertPool(pool)
	uc.Init()
	return uc
}

// TestDoHResolve_OversizedBody_Rejected locks in the fix for
// github.com/Control-D-Inc/ctrld/issues/312: a malicious DoH upstream
// returning a body larger than the DNS protocol allows must be rejected
// with an explicit size error rather than buffered into ctrld memory.
func TestDoHResolve_OversizedBody_Rejected(t *testing.T) {
	const oversized = 2 * 1024 * 1024 // far past dohMaxResponseSize (~64 KiB)
	var written atomic.Int64
	srv := httptest.NewUnstartedServer(oversizedDoHHandler(http.StatusOK, oversized, &written))
	testCert := generateTestCertificate(t)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	uc := dohUpstreamForTLSServer(t, srv)
	r, err := NewResolver(uc)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	answer, err := r.Resolve(ctx, msg)
	if err == nil {
		t.Fatalf("Resolve unexpectedly succeeded; answer=%v", answer)
	}
	if !strings.Contains(err.Error(), "maximum DNS message size") {
		t.Fatalf("error %q does not mention the size cap", err)
	}
	if answer != nil {
		t.Fatalf("Resolve returned non-nil answer alongside error: %v", answer)
	}
	if got := written.Load(); got >= int64(oversized) {
		t.Fatalf("server wrote the entire %d-byte body before client tore down (wrote=%d) — cap not effective", oversized, got)
	}
}

// TestDoHResolve_NonOKStatus_BoundedErrorBody locks in that a non-200
// response with a huge body does not pull the body fully into ctrld
// memory just to format an error string.
func TestDoHResolve_NonOKStatus_BoundedErrorBody(t *testing.T) {
	const huge = 8 * 1024 * 1024
	var written atomic.Int64
	srv := httptest.NewUnstartedServer(oversizedDoHHandler(http.StatusBadGateway, huge, &written))
	testCert := generateTestCertificate(t)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	uc := dohUpstreamForTLSServer(t, srv)
	r, err := NewResolver(uc)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	answer, err := r.Resolve(ctx, msg)
	if err == nil {
		t.Fatalf("Resolve unexpectedly succeeded; answer=%v", answer)
	}
	if !strings.Contains(err.Error(), "status: 502") {
		t.Fatalf("error %q does not surface the upstream status", err)
	}
	if answer != nil {
		t.Fatalf("Resolve returned non-nil answer alongside error: %v", answer)
	}
	if got := written.Load(); got > 1024*1024 {
		t.Fatalf("server wrote %d bytes before client tore down — error path is reading too much body", got)
	}
}

// TestDoHResolve_OversizedBody_DoH3 mirrors the DoH oversized-body check
// on the HTTP/3 transport, since github-312 specifically reproduced the
// OOM via DoH3.
func TestDoHResolve_OversizedBody_DoH3(t *testing.T) {
	const oversized = 2 * 1024 * 1024
	testCert := generateTestCertificate(t)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	h3 := &http3.Server{
		Handler: oversizedDoHHandler(http.StatusOK, oversized, nil),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{testCert.tlsCert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() {
		if err := h3.Serve(udpConn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("h3 server: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = h3.Close()
		_ = udpConn.Close()
	})
	time.Sleep(100 * time.Millisecond)

	uc := doh3UpstreamForAddr(t, udpConn.LocalAddr().String(), testCert.cert)
	r, err := NewResolver(uc)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	answer, err := r.Resolve(ctx, msg)
	if err == nil {
		t.Fatalf("Resolve unexpectedly succeeded; answer=%v", answer)
	}
	if !strings.Contains(err.Error(), "maximum DNS message size") {
		t.Fatalf("error %q does not mention the size cap", err)
	}
	if answer != nil {
		t.Fatalf("Resolve returned non-nil answer alongside error: %v", answer)
	}
}

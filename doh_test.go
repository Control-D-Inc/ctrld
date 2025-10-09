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

	ctx := context.Background()
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.uc.Init(ctx)
			tc.uc.SetupBootstrapIP(ctx)
			r, err := NewResolver(ctx, tc.uc)
			if err != nil {
				t.Fatal(err)
			}
			msg := new(dns.Msg)
			msg.SetQuestion("verify.controld.com.", dns.TypeA)
			msg.RecursionDesired = true
			_, err = r.Resolve(ctx, msg)
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

package certs

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

// The fixtures are embedded rather than read from disk: test:windows runs
// cross-compiled test binaries with no source checkout (GIT_STRATEGY: none).
//
//go:embed testdata/*.pem
var testdata embed.FS

// Chains served by the eMudhra disclosure test hosts
// (https://emudhra.we-have-a-problem.com/chains.zip, captured 2026-10-20).
// Each file is leaf first, then the intermediates the host sends. The
// intermediate keys are publicly recoverable (CVE-2026-111943), so none of
// these chains may verify.
var emudhraChains = []string{
	// EM DV TLS CA - G3B -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3
	"dv-g3b-emudhra.we-have-a-problem.com.pem",
	// EM DV TLS CA - G3B cross-signed by AAA Certificate Services
	"dv-g3b-aaa-emudhra.we-have-a-problem.com.pem",
}

// verifyAt is inside every certificate's validity window, so a rejection
// below comes from trust, not from expiry.
var verifyAt = time.Date(2026, time.October, 21, 0, 0, 0, 0, time.UTC)

func readCerts(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	b, err := testdata.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return parsePEMCerts(t, name, b)
}

func parsePEMCerts(t *testing.T, name string, b []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		t.Fatalf("%s: no certificates", name)
	}
	return certs
}

func verifyChain(t *testing.T, name string, roots *x509.CertPool) error {
	t.Helper()
	chain := readCerts(t, name)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       chain[0].Subject.CommonName,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   verifyAt,
	})
	return err
}

// requireTrustRejection fails unless err is a trust rejection. Any other
// verification error (hostname mismatch, expiry after verifyAt drifts, a
// broken fixture) would let the chain checks pass without proving anything.
func requireTrustRejection(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	t.Logf("%s: %v", name, err)
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		t.Errorf("%s: rejected for hostname, not trust: %v", name, err)
	}
	var invErr x509.CertificateInvalidError
	if errors.As(err, &invErr) && invErr.Reason == x509.Expired {
		t.Errorf("%s: rejected for expiry, not trust: %v", name, err)
	}
}

// The embedded bundle is the only trust store on DD-WRT (upstream DoH/DoT/DoQ)
// and on Android (Control D API), so it must not contain the affected roots.
// This checks the bundle contents directly: on a fixed toolchain the chain
// verification below passes even with the affected roots present.
func TestCACertBundleExcludesAffectedEMudhraRoots(t *testing.T) {
	bundle := parsePEMCerts(t, "cacert.pem", caRoots)
	for _, root := range readCerts(t, "emudhra-roots.pem") {
		for _, c := range bundle {
			// Raw catches the exact certificate; subject + key also catches a
			// re-issued form of the same root.
			if bytes.Equal(c.Raw, root.Raw) ||
				(bytes.Equal(c.RawSubject, root.RawSubject) &&
					bytes.Equal(c.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo)) {
				t.Errorf("embedded cacert.pem contains affected root %q", root.Subject.CommonName)
			}
		}
	}
}

func TestCACertPoolRejectsCompromisedEMudhraChains(t *testing.T) {
	for _, name := range emudhraChains {
		err := verifyChain(t, name, CACertPool())
		if err == nil {
			t.Errorf("%s: embedded cacert.pem trusts a compromised eMudhra intermediate", name)
			continue
		}
		requireTrustRejection(t, name, err)
	}
}

// Every other platform verifies against the OS store, which may still carry
// the affected roots. Go 1.26.10 / 1.27.3 reject the compromised intermediates
// inside crypto/x509 regardless of roots; this fails if the build toolchain
// predates that fix.
func TestToolchainRejectsCompromisedEMudhraIntermediates(t *testing.T) {
	roots := x509.NewCertPool()
	for _, c := range readCerts(t, "emudhra-roots.pem") {
		roots.AddCert(c)
	}
	for _, name := range emudhraChains {
		err := verifyChain(t, name, roots)
		if err == nil {
			t.Errorf("%s: crypto/x509 accepted a compromised eMudhra intermediate with its root trusted; build with go1.26.10+ or go1.27.3+", name)
			continue
		}
		requireTrustRejection(t, name, err)
	}
}

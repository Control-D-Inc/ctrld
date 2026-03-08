package ctrld

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"

	"github.com/cuonglm/osinfo"

	"github.com/miekg/dns"
)

const (
	dohMacHeader          = "x-cd-mac"
	dohIPHeader           = "x-cd-ip"
	dohHostHeader         = "x-cd-host"
	dohOsHeader           = "x-cd-os"
	dohClientIDPrefHeader = "x-cd-cpref"
	headerApplicationDNS  = "application/dns-message"
)

// EncodeOsNameMap provides mapping from OS name to a shorter string, used for encoding x-cd-os value.
var EncodeOsNameMap = map[string]string{
	"windows": "1",
	"darwin":  "2",
	"linux":   "3",
	"freebsd": "4",
}

// DecodeOsNameMap provides mapping from encoded OS name to real value, used for decoding x-cd-os value.
var DecodeOsNameMap = map[string]string{}

// EncodeArchNameMap provides mapping from OS arch to a shorter string, used for encoding x-cd-os value.
var EncodeArchNameMap = map[string]string{
	"amd64":  "1",
	"arm64":  "2",
	"arm":    "3",
	"386":    "4",
	"mips":   "5",
	"mipsle": "6",
	"mips64": "7",
}

// DecodeArchNameMap provides mapping from encoded OS arch to real value, used for decoding x-cd-os value.
var DecodeArchNameMap = map[string]string{}

func init() {
	for k, v := range EncodeOsNameMap {
		DecodeOsNameMap[v] = k
	}
	for k, v := range EncodeArchNameMap {
		DecodeArchNameMap[v] = k
	}
}

var dohOsHeaderValue = sync.OnceValue(func() string {
	oi := osinfo.New()
	return strings.Join([]string{EncodeOsNameMap[runtime.GOOS], EncodeArchNameMap[runtime.GOARCH], oi.Dist}, "-")
})()

func newDohResolver(uc *UpstreamConfig) *dohResolver {
	r := &dohResolver{
		endpoint:          uc.u,
		isDoH3:            uc.Type == ResolverTypeDOH3,
		http3RoundTripper: uc.http3RoundTripper,
		uc:                uc,
	}
	return r
}

type dohResolver struct {
	uc                *UpstreamConfig
	endpoint          *url.URL
	isDoH3            bool
	http3RoundTripper http.RoundTripper
}

// Resolve performs DNS query with given DNS message using DOH protocol.
func (r *dohResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding.EncodeToString(data)
	query := r.endpoint.Query()
	query.Add("dns", enc)

	endpoint := *r.endpoint
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	addHeader(ctx, req, r.uc)
	dnsTyp := uint16(0)
	if len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	c := http.Client{Transport: r.uc.dohTransport(dnsTyp)}
	if r.isDoH3 {
		transport := r.uc.doh3Transport(dnsTyp)
		if transport == nil {
			return nil, errors.New("DoH3 is not supported")
		}
		c.Transport = transport
	}
	resp, err := c.Do(req)
	if err != nil && r.uc.FallbackToDirectIP() {
		retryCtx, cancel := r.uc.Context(context.WithoutCancel(ctx))
		defer cancel()
		Log(ctx, ProxyLogger.Load().Warn().Err(err), "retrying request after fallback to direct ip")
		resp, err = c.Do(req.Clone(retryCtx))
	}
	if err != nil {
		err = wrapUrlError(err)
		if r.isDoH3 {
			if closer, ok := c.Transport.(io.Closer); ok {
				closer.Close()
			}
		}
		return nil, fmt.Errorf("could not perform request: %w", err)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read message from response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong response from DOH server, got: %s, status: %d", string(buf), resp.StatusCode)
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(buf); err != nil {
		return nil, fmt.Errorf("answer.Unpack: %w", err)
	}
	return answer, nil
}

// addHeader adds necessary HTTP header to request based on upstream config.
func addHeader(ctx context.Context, req *http.Request, uc *UpstreamConfig) {
	printed := false
	dohHeader := make(http.Header)
	if uc.UpstreamSendClientInfo() {
		if ci, ok := ctx.Value(ClientInfoCtxKey{}).(*ClientInfo); ok && ci != nil {
			printed = ci.Mac != "" || ci.IP != "" || ci.Hostname != ""
			switch {
			case uc.IsControlD():
				dohHeader = newControlDHeaders(ci)
			case uc.isNextDNS():
				dohHeader = newNextDNSHeaders(ci)
		        default:
			     // For custom upstreams with send_client_info enabled, use ControlD-style headers	
			     dohHeader = newControlDHeaders(ci)
			}
		}
	}
	if printed {
		Log(ctx, ProxyLogger.Load().Debug(), "sending request header: %v", dohHeader)
	}
	dohHeader.Set("Content-Type", headerApplicationDNS)
	dohHeader.Set("Accept", headerApplicationDNS)
	req.Header = dohHeader
}

// newControlDHeaders returns DoH/Doh3 HTTP request headers for ControlD upstream.
func newControlDHeaders(ci *ClientInfo) http.Header {
	header := make(http.Header)
	if ci.Mac != "" {
		header.Set(dohMacHeader, ci.Mac)
	}
	if ci.IP != "" {
		header.Set(dohIPHeader, ci.IP)
	}
	if ci.Hostname != "" {
		header.Set(dohHostHeader, ci.Hostname)
	}
	if ci.Self {
		header.Set(dohOsHeader, dohOsHeaderValue)
	}
	switch ci.ClientIDPref {
	case "mac":
		header.Set(dohClientIDPrefHeader, "1")
	case "host":
		header.Set(dohClientIDPrefHeader, "2")
	}
	return header
}

// newNextDNSHeaders returns DoH/Doh3 HTTP request headers for nextdns upstream.
// https://github.com/nextdns/nextdns/blob/v1.41.0/resolver/doh.go#L100
func newNextDNSHeaders(ci *ClientInfo) http.Header {
	header := make(http.Header)
	if ci.Mac != "" {
		// https: //github.com/nextdns/nextdns/blob/v1.41.0/run.go#L543
		header.Set("X-Device-Model", "mac:"+ci.Mac[:8])
	}
	if ci.IP != "" {
		header.Set("X-Device-Ip", ci.IP)
	}
	if ci.Hostname != "" {
		header.Set("X-Device-Name", ci.Hostname)
	}
	return header
}

// wrapCertificateVerificationError wraps a certificate verification error with additional context about the certificate issuer.
// It extracts information like the issuer, organization, and subject from the certificate for a more descriptive error output.
// If no certificate-related information is available, it simply returns the original error unmodified.
func wrapCertificateVerificationError(err error) error {
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		if len(tlsErr.UnverifiedCertificates) > 0 {
			cert := tlsErr.UnverifiedCertificates[0]
			// Extract a more user-friendly issuer name
			var issuer string
			var organization string
			if len(cert.Issuer.Organization) > 0 {
				organization = cert.Issuer.Organization[0]
				issuer = organization
			} else if cert.Issuer.CommonName != "" {
				issuer = cert.Issuer.CommonName
			} else {
				issuer = cert.Issuer.String()
			}

			// Get the organization from the subject field as well
			if len(cert.Subject.Organization) > 0 {
				organization = cert.Subject.Organization[0]
			}

			// Extract the subject information
			subjectCN := cert.Subject.CommonName
			if subjectCN == "" && len(cert.Subject.Organization) > 0 {
				subjectCN = cert.Subject.Organization[0]
			}
			return fmt.Errorf("%w: %s, %s, %s", tlsErr, subjectCN, organization, issuer)
		}
	}
	return err
}

// wrapUrlError inspects and wraps a URL error, focusing on certificate verification errors for detailed context.
func wrapUrlError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var tlsErr *tls.CertificateVerificationError
		if errors.As(urlErr.Err, &tlsErr) {
			urlErr.Err = wrapCertificateVerificationError(tlsErr)
			return urlErr
		}
	}
	return err
}

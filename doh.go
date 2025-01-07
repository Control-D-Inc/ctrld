package ctrld

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

	if ci, ok := ctx.Value(ClientInfoCtxKey{}).(*ClientInfo); ok && ci != nil {
		switch r.uc.ClientIdType {
		case "subdomain":
			endpoint.Host = subdomainFromClientInfo(r.uc, ci) + "." + endpoint.Host

		case "path":
			endpoint.Path = endpoint.Path + pathFromClientInfo(r.uc, ci)
		}
	}

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
	if err != nil {
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
			case uc.IsControlD() || uc.ClientIdType == "header":
				dohHeader = newControlDHeaders(ci)
			case uc.isNextDNS():
				dohHeader = newNextDNSHeaders(ci)
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

func subdomainFromClientInfo(uc *UpstreamConfig, ci *ClientInfo) string {
	switch uc.ClientId {
	case "mac":
		return strings.ReplaceAll(ci.Mac, ":", "-")
	case "host":
		return subdomainFromHostname(ci.Hostname)
	}
	return "" // TODO; fix this
}

func pathFromClientInfo(uc *UpstreamConfig, ci *ClientInfo) string {
	switch uc.ClientId {
	case "mac":
		return "/" + strings.ReplaceAll(ci.Mac, ":", "-")
	case "host":
		return "/" + url.PathEscape(ci.Hostname)
	}
	return "" // TODO; fix this
}

func subdomainFromHostname(hostname string) string {
	// Define a regular expression to match allowed characters
	re := regexp.MustCompile(`[^a-zA-Z0-9-]`)

	// Remove chars not allowed in subdomain
	subdomain := re.ReplaceAllString(hostname, "")

	// Replace spaces with --
	subdomain = strings.ReplaceAll(subdomain, " ", "--")

	// Trim leading and trailing hyphens
	subdomain = strings.Trim(subdomain, "-")

	return subdomain
}

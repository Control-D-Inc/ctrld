package controld

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/ddwrt"
)

const (
	apiDomainCom       = "api.controld.com"
	apiDomainComIPv4   = "147.185.34.1"
	apiDomainComIPv6   = "2606:1a40:3::1"
	apiDomainDev       = "api.controld.dev"
	apiDomainDevIPv4   = "23.171.240.84"
	apiURLCom          = "https://api.controld.com"
	apiURLDev          = "https://api.controld.dev"
	resolverDataURLCom = apiURLCom + "/utility"
	resolverDataURLDev = apiURLDev + "/utility"
	logURLCom          = apiURLCom + "/logs"
	logURLDev          = apiURLDev + "/logs"
	InvalidConfigCode  = 40402
	defaultTimeout     = 20 * time.Second
	sendLogTimeout     = 300 * time.Second
)

// ResolverConfig represents Control D resolver data.
type ResolverConfig struct {
	DOH   string `json:"doh"`
	Ctrld struct {
		CustomConfig     string `json:"custom_config"`
		CustomLastUpdate int64  `json:"custom_last_update"`
		VersionTarget    string `json:"version_target"`
	} `json:"ctrld"`
	Exclude         []string `json:"exclude"`
	UID             string   `json:"uid"`
	DeactivationPin *int64   `json:"deactivation_pin,omitempty"`
}

type utilityResponse struct {
	Success bool `json:"success"`
	Body    struct {
		Resolver ResolverConfig `json:"resolver"`
	} `json:"body"`
}

type ErrorResponse struct {
	ErrorField struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func (u ErrorResponse) Error() string {
	return u.ErrorField.Message
}

type utilityRequest struct {
	UID      string `json:"uid"`
	ClientID string `json:"client_id,omitempty"`
}

// UtilityOrgRequest contains request data for calling Org API.
type UtilityOrgRequest struct {
	ProvToken string `json:"prov_token"`
	Hostname  string `json:"hostname"`
}

// LogsRequest contains request data for sending runtime logs to API.
type LogsRequest struct {
	UID  string        `json:"uid"`
	Data io.ReadCloser `json:"-"`
}

// FetchResolverConfig fetch Control D config for given uid.
func FetchResolverConfig(ctx context.Context, rawUID, version string, cdDev bool) (*ResolverConfig, error) {
	uid, clientID := ParseRawUID(rawUID)
	req := utilityRequest{UID: uid}
	if clientID != "" {
		req.ClientID = clientID
	}
	body, _ := json.Marshal(req)
	return postUtilityAPI(ctx, version, cdDev, false, bytes.NewReader(body))
}

// FetchResolverUID fetch resolver uid from provision token.
func FetchResolverUID(ctx context.Context, req *UtilityOrgRequest, version string, cdDev bool) (*ResolverConfig, error) {
	if req == nil {
		return nil, errors.New("invalid request")
	}
	hostname := req.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	body, _ := json.Marshal(UtilityOrgRequest{ProvToken: req.ProvToken, Hostname: hostname})
	return postUtilityAPI(ctx, version, cdDev, false, bytes.NewReader(body))
}

// UpdateCustomLastFailed calls API to mark custom config is bad.
func UpdateCustomLastFailed(ctx context.Context, rawUID, version string, cdDev, lastUpdatedFailed bool) (*ResolverConfig, error) {
	uid, clientID := ParseRawUID(rawUID)
	req := utilityRequest{UID: uid}
	if clientID != "" {
		req.ClientID = clientID
	}
	body, _ := json.Marshal(req)
	return postUtilityAPI(ctx, version, cdDev, true, bytes.NewReader(body))
}

func postUtilityAPI(ctx context.Context, version string, cdDev, lastUpdatedFailed bool, body io.Reader) (*ResolverConfig, error) {
	apiUrl := resolverDataURLCom
	if cdDev {
		apiUrl = resolverDataURLDev
	}
	req, err := http.NewRequest("POST", apiUrl, body)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	q := req.URL.Query()
	q.Set("platform", "ctrld")
	q.Set("version", version)
	if lastUpdatedFailed {
		q.Set("custom_last_failed", "1")
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/json")
	transport := apiTransport(ctx, cdDev)
	client := &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
	resp, err := doWithFallback(ctx, client, req, apiServerIP(cdDev))
	if err != nil {
		return nil, fmt.Errorf("postUtilityAPI client.Do: %w", err)
	}
	defer resp.Body.Close()
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp := &ErrorResponse{}
		if err := d.Decode(errResp); err != nil {
			return nil, err
		}
		return nil, errResp
	}

	ur := &utilityResponse{}
	if err := d.Decode(ur); err != nil {
		return nil, err
	}
	return &ur.Body.Resolver, nil
}

// SendLogs sends runtime log to ControlD API.
func SendLogs(ctx context.Context, lr *LogsRequest, cdDev bool) error {
	defer lr.Data.Close()
	apiUrl := logURLCom
	if cdDev {
		apiUrl = logURLDev
	}
	req, err := http.NewRequest("POST", apiUrl, lr.Data)
	if err != nil {
		return fmt.Errorf("http.NewRequest: %w", err)
	}
	q := req.URL.Query()
	q.Set("uid", lr.UID)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	transport := apiTransport(ctx, cdDev)
	client := &http.Client{
		Timeout:   sendLogTimeout,
		Transport: transport,
	}
	resp, err := doWithFallback(ctx, client, req, apiServerIP(cdDev))
	if err != nil {
		return fmt.Errorf("SendLogs client.Do: %w", err)
	}
	defer resp.Body.Close()
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp := &ErrorResponse{}
		if err := d.Decode(errResp); err != nil {
			return err
		}
		return errResp
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ParseRawUID parse the input raw UID, returning real UID and ClientID.
// The raw UID can have 2 forms:
//
// - <uid>
// - <uid>/<client_id>
func ParseRawUID(rawUID string) (string, string) {
	uid, clientID, _ := strings.Cut(rawUID, "/")
	return uid, clientID
}

// apiTransport returns an HTTP transport for connecting to ControlD API endpoint.
func apiTransport(loggerCtx context.Context, cdDev bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		apiDomain := apiDomainCom
		apiIpsV4 := []string{apiDomainComIPv4}
		apiIpsV6 := []string{apiDomainComIPv6}
		apiIPs := []string{apiDomainComIPv4, apiDomainComIPv6}
		if cdDev {
			apiDomain = apiDomainDev
			apiIpsV4 = []string{apiDomainDevIPv4}
			apiIpsV6 = []string{}
			apiIPs = []string{apiDomainDevIPv4}
		}

		ips := ctrld.LookupIP(loggerCtx, apiDomain)
		if len(ips) == 0 {
			logger := ctrld.LoggerFromCtx(loggerCtx)
			logger.Warn().Msgf("No IPs found for %s, use direct IPs: %v", apiDomain, apiIPs)
			ips = apiIPs
		}

		// Separate IPv4 and IPv6 addresses
		var ipv4s, ipv6s []string
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				ipv6s = append(ipv6s, ip)
			} else {
				ipv4s = append(ipv4s, ip)
			}
		}

		dial := func(ctx context.Context, network string, addrs []string) (net.Conn, error) {
			d := &ctrldnet.ParallelDialer{}
			logger := ctrld.LoggerFromCtx(loggerCtx)
			return d.DialContext(ctx, network, addrs, logger.Logger)
		}
		_, port, _ := net.SplitHostPort(addr)

		// Try IPv4 first
		if len(ipv4s) > 0 {
			if conn, err := dial(ctx, "tcp4", addrsFromPort(ipv4s, port)); err == nil {
				return conn, nil
			}
		}
		// Fallback to direct IPv4
		if conn, err := dial(ctx, "tcp4", addrsFromPort(apiIpsV4, port)); err == nil {
			return conn, nil
		}

		// Fallback to IPv6 if available
		if len(ipv6s) > 0 {
			if conn, err := dial(ctx, "tcp6", addrsFromPort(ipv6s, port)); err == nil {
				return conn, nil
			}
		}
		// Fallback to direct IPv6
		return dial(ctx, "tcp6", addrsFromPort(apiIpsV6, port))
	}
	if router.Name() == ddwrt.Name || runtime.GOOS == "android" {
		transport.TLSClientConfig = &tls.Config{RootCAs: certs.CACertPool()}
	}
	return transport
}

func addrsFromPort(ips []string, port string) []string {
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = net.JoinHostPort(ip, port)
	}
	return addrs
}

func doWithFallback(ctx context.Context, client *http.Client, req *http.Request, apiIp string) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		logger := ctrld.LoggerFromCtx(ctx)
		logger.Warn().Err(err).Msgf("failed to send request, fallback to direct IP: %s", apiIp)
		ipReq := req.Clone(req.Context())
		ipReq.Host = apiIp
		ipReq.URL.Host = apiIp
		resp, err = client.Do(ipReq)
	}
	return resp, err
}

// apiServerIP returns the direct IP to connect to API server.
func apiServerIP(cdDev bool) string {
	if cdDev {
		return apiDomainDevIPv4
	}
	return apiDomainComIPv4
}

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
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
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

// Provisioning-token rejection reasons the API sends in error.metadata.reason
// (HTTP 400, code 40003). This list can grow; a value outside it is not an
// error, just one cmd/cli does not classify yet.
const (
	ReasonTokenInvalid      = "token_invalid"
	ReasonTokenExpired      = "token_expired"
	ReasonTokenLimitReached = "token_limit_reached"
	ReasonTokenDisabled     = "token_disabled"
)

// ResolverConfig represents Control D resolver data.
type ResolverConfig struct {
	DOH   string `json:"doh"`
	Ctrld struct {
		CustomConfig     string `json:"custom_config"`
		CustomLastUpdate int64  `json:"custom_last_update"`
		VersionTarget    string `json:"version_target"`
	} `json:"ctrld"`
	Exclude []string `json:"exclude"`
	// DestinationIPs is the organization's effective Allowed Destination IP list:
	// the entries configured for this endpoint's organization plus any inherited
	// from a parent organization. Each entry is an IPv4/IPv6 address or a CIDR
	// (the API reports single-host entries as bare addresses, not /32 or /128).
	// Under Firewall Mode these destinations stay reachable without a prior DNS
	// lookup; see cmd/cli/firewall.go.
	DestinationIPs  []string `json:"destination_ips"`
	UID             string   `json:"uid"`
	DeactivationPin *int64   `json:"deactivation_pin,omitempty"`
}

type utilityResponse struct {
	Success bool `json:"success"`
	Body    struct {
		Resolver ResolverConfig `json:"resolver"`
	} `json:"body"`
}

// errorMetadata carries additive, optional detail on top of Code/Message.
// Older API deployments omit it, so it must decode to its zero value rather
// than fail the whole response. Its custom UnmarshalJSON gives the same
// tolerance to a malformed value: a metadata that is not an object, or a
// Reason that is not a string (a number, an object, or null), degrades to
// the zero value rather than failing the response that contains it.
type errorMetadata struct {
	// Reason is a machine-readable rejection reason sent on provisioning-token
	// errors (HTTP 400, code 40003): token_invalid, token_expired,
	// token_limit_reached, or token_disabled. Empty when absent or malformed;
	// callers must treat any other value as unknown rather than reject the
	// response.
	Reason string `json:"reason"`
}

func (m *errorMetadata) UnmarshalJSON(data []byte) error {
	var raw struct {
		Reason json.RawMessage `json:"reason"`
	}
	// Best-effort: a metadata that is not an object, or a reason that is not
	// a string (number, object, null), leaves the zero value instead of
	// failing this decode. Code and Message still classify the failure.
	if err := json.Unmarshal(data, &raw); err != nil {
		*m = errorMetadata{}
		return nil
	}
	_ = json.Unmarshal(raw.Reason, &m.Reason)
	return nil
}

type ErrorResponse struct {
	ErrorField struct {
		Message  string        `json:"message"`
		Code     int           `json:"code"`
		Metadata errorMetadata `json:"metadata"`
	} `json:"error"`
	// StatusCode is the HTTP status the API answered with. It is not part of the JSON
	// body: this type is built for *any* non-200 whose body decodes, so the body alone
	// cannot tell a permanent rejection of the request from a transient server-side
	// failure, and callers that act differently on the two need the status to tell them
	// apart. Zero means the status was not recorded.
	StatusCode int `json:"-"`
}

func (u ErrorResponse) Error() string {
	return u.ErrorField.Message
}

// apiErrorFromResponse builds the error for a non-200 API answer, recording the HTTP
// status alongside the decoded body.
//
// The status is what tells a caller whether the answer will change on a retry: this type
// is built for every non-200 whose body decodes, so a 502 from a load balancer and a 404
// for a deleted device are otherwise indistinguishable. Both response paths go through
// here so neither can decode a body and forget to record it.
func apiErrorFromResponse(statusCode int, d *json.Decoder) (*ErrorResponse, error) {
	errResp := &ErrorResponse{StatusCode: statusCode}
	if err := d.Decode(errResp); err != nil {
		return nil, err
	}
	// Decode fills exported fields from the body; StatusCode is json:"-", so it survives.
	errResp.StatusCode = statusCode
	return errResp, nil
}

type utilityRequest struct {
	UID      string            `json:"uid"`
	ClientID string            `json:"client_id,omitempty"`
	Metadata map[string]string `json:"metadata"`
}

// UtilityOrgRequest contains request data for calling Org API.
type UtilityOrgRequest struct {
	ProvToken string            `json:"prov_token"`
	Hostname  string            `json:"hostname"`
	Metadata  map[string]string `json:"metadata"`
}

// ResolverConfigRequest contains request data for fetching resolver config.
type ResolverConfigRequest struct {
	RawUID   string
	Version  string
	Metadata map[string]string
}

// LogsRequest contains request data for sending runtime logs to API.
type LogsRequest struct {
	UID  string        `json:"uid"`
	Data io.ReadCloser `json:"-"`
}

// FetchResolverConfig fetch Control D config for a given request.
func FetchResolverConfig(ctx context.Context, req *ResolverConfigRequest, cdDev bool) (*ResolverConfig, error) {
	logger := ctrld.LoggerFromCtx(ctx)
	ctrld.Log(ctx, logger.Debug(), "Fetching ControlD resolver configuration")

	uid, clientID := ParseRawUID(req.RawUID)
	ctrld.Log(ctx, logger.Debug(), "Parsed UID: %s, ClientID: %s", uid, clientID)

	uReq := utilityRequest{
		UID:      uid,
		Metadata: req.Metadata,
	}
	if clientID != "" {
		uReq.ClientID = clientID
		ctrld.Log(ctx, logger.Debug(), "Including client ID in request")
	}
	body, _ := json.Marshal(uReq)
	ctrld.Log(ctx, logger.Debug(), "Sending resolver config request to ControlD API")
	return postUtilityAPI(ctx, req.Version, cdDev, false, bytes.NewReader(body))
}

// FetchResolverUID fetch resolver uid from a given request.
func FetchResolverUID(ctx context.Context, req *UtilityOrgRequest, version string, cdDev bool) (*ResolverConfig, error) {
	logger := ctrld.LoggerFromCtx(ctx)
	ctrld.Log(ctx, logger.Debug(), "Fetching resolver UID from provision token")

	if req == nil {
		ctrld.Log(ctx, logger.Error(), "Invalid request: request is nil")
		return nil, errors.New("invalid request")
	}

	hostname := req.Hostname
	if req.Hostname == "" {
		hostname, _ = preferredHostname()
		ctrld.Log(ctx, logger.Debug(), "Using system hostname: %s", hostname)
		req.Hostname = hostname
	} else {
		ctrld.Log(ctx, logger.Debug(), "Using provided hostname: %s", hostname)
	}

	// Include all hostname sources in metadata so the API can pick the
	// best one if the primary looks generic (e.g., "Mac", "Mac.lan").
	if req.Metadata == nil {
		req.Metadata = make(map[string]string)
	}
	for k, v := range hostnameHints() {
		req.Metadata["hostname_"+k] = v
	}

	ctrld.Log(ctx, logger.Debug(), "Sending UID request to ControlD API")
	body, _ := json.Marshal(req)
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
	return postUtilityAPI(ctx, version, cdDev, lastUpdatedFailed, bytes.NewReader(body))
}

func postUtilityAPI(ctx context.Context, version string, cdDev, lastUpdatedFailed bool, body io.Reader) (*ResolverConfig, error) {
	logger := ctrld.LoggerFromCtx(ctx)
	ctrld.Log(ctx, logger.Debug(), "Posting utility API request")

	apiUrl := resolverDataURLCom
	if cdDev {
		apiUrl = resolverDataURLDev
		ctrld.Log(ctx, logger.Debug(), "Using development API URL: %s", apiUrl)
	} else {
		ctrld.Log(ctx, logger.Debug(), "Using production API URL: %s", apiUrl)
	}

	ctrld.Log(ctx, logger.Debug(), "Creating HTTP request")
	// Context-bound so an in-flight request is abandoned when the caller is
	// cancelled - a service stop during API preflight must not wait out the
	// request timeout, let alone keep retrying.
	req, err := http.NewRequestWithContext(ctx, "POST", apiUrl, body)
	if err != nil {
		ctrld.Log(ctx, logger.Error(), "Failed to create HTTP request: %v", err)
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}

	ctrld.Log(ctx, logger.Debug(), "Setting request parameters")
	q := req.URL.Query()
	q.Set("platform", "ctrld")
	q.Set("version", version)
	if lastUpdatedFailed {
		q.Set("custom_last_failed", "1")
		ctrld.Log(ctx, logger.Debug(), "Marking custom config as failed")
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/json")

	ctrld.Log(ctx, logger.Debug(), "Setting up API transport")
	transport := apiTransport(ctx, cdDev)
	client := &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}

	ctrld.Log(ctx, logger.Debug(), "Sending request to ControlD API")
	resp, err := doWithFallback(ctx, client, req, apiServerIP(cdDev))
	if err != nil {
		ctrld.Log(ctx, logger.Error(), "Failed to send request to ControlD API: %v", err)
		return nil, fmt.Errorf("postUtilityAPI client.Do: %w", err)
	}
	defer resp.Body.Close()

	ctrld.Log(ctx, logger.Debug(), "Processing API response")
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp, err := apiErrorFromResponse(resp.StatusCode, d)
		if err != nil {
			ctrld.Log(ctx, logger.Error(), "Failed to decode error response: %v", err)
			return nil, err
		}
		ctrld.Log(ctx, logger.Error(), "ControlD API returned error: %s", errResp.Error())
		return nil, errResp
	}

	ur := &utilityResponse{}
	if err := d.Decode(ur); err != nil {
		ctrld.Log(ctx, logger.Error(), "Failed to decode utility response: %v", err)
		return nil, err
	}

	ctrld.Log(ctx, logger.Debug(), "Successfully received resolver configuration")
	return &ur.Body.Resolver, nil
}

// SendLogs sends runtime log to ControlD API.
func SendLogs(ctx context.Context, lr *LogsRequest, cdDev bool) error {
	logger := ctrld.LoggerFromCtx(ctx)
	ctrld.Log(ctx, logger.Debug(), "Sending runtime logs to ControlD API")

	defer lr.Data.Close()
	apiUrl := logURLCom
	if cdDev {
		apiUrl = logURLDev
	}

	ctrld.Log(ctx, logger.Debug(), "Creating HTTP request for log upload")
	req, err := http.NewRequestWithContext(ctx, "POST", apiUrl, lr.Data)
	if err != nil {
		ctrld.Log(ctx, logger.Error(), "Failed to create HTTP request: %v", err)
		return fmt.Errorf("http.NewRequest: %w", err)
	}
	q := req.URL.Query()
	q.Set("uid", lr.UID)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	ctrld.Log(ctx, logger.Debug(), "Setting up API transport")
	transport := apiTransport(ctx, cdDev)
	client := &http.Client{
		Timeout:   sendLogTimeout,
		Transport: transport,
	}

	ctrld.Log(ctx, logger.Debug(), "Sending log data to ControlD API")
	resp, err := doWithFallback(ctx, client, req, apiServerIP(cdDev))
	if err != nil {
		ctrld.Log(ctx, logger.Error(), "Failed to send logs to ControlD API: %v", err)
		return fmt.Errorf("SendLogs client.Do: %w", err)
	}
	defer resp.Body.Close()

	ctrld.Log(ctx, logger.Debug(), "Processing API response")
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		errResp, err := apiErrorFromResponse(resp.StatusCode, d)
		if err != nil {
			ctrld.Log(ctx, logger.Error(), "Failed to decode error response: %v", err)
			return err
		}
		ctrld.Log(ctx, logger.Error(), "ControlD API returned error: %s", errResp.Error())
		return errResp
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	ctrld.Log(ctx, logger.Debug(), "Runtime logs sent successfully to ControlD API")
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

// APIDomain returns the ControlD API hostname for the environment.
func APIDomain(cdDev bool) string {
	if cdDev {
		return apiDomainDev
	}
	return apiDomainCom
}

// APIEndpointIPs returns the addresses the API transport dials directly when the
// hostname cannot be resolved.
//
// Exported because Firewall Mode has to permit them: it blocks every destination
// ctrld did not resolve through its own listener, and the API is resolved through
// the OS resolver by LookupIP instead, so nothing ever teaches the allowlist about
// it. Left unpermitted, ctrld's own block-all filters deny its API socket - which
// is what stranded the 2026-08-16 Windows run with 920 WSAEACCES denials and not
// one successful configuration refresh in 38 hours.
func APIEndpointIPs(cdDev bool) []string {
	if cdDev {
		return []string{apiDomainDevIPv4}
	}
	return []string{apiDomainComIPv4, apiDomainComIPv6}
}

// apiDirectIPs splits APIEndpointIPs into its IPv4 and IPv6 halves.
func apiDirectIPs(cdDev bool) (v4, v6 []string) {
	for _, ip := range APIEndpointIPs(cdDev) {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	return v4, v6
}

// apiTransport returns an HTTP transport for connecting to ControlD API endpoint.
func apiTransport(loggerCtx context.Context, cdDev bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		apiDomain := APIDomain(cdDev)
		apiIpsV4, apiIpsV6 := apiDirectIPs(cdDev)
		apiIPs := APIEndpointIPs(cdDev)

		ips := ctrld.LookupIP(loggerCtx, apiDomain)
		if len(ips) == 0 {
			logger := ctrld.LoggerFromCtx(loggerCtx)
			logger.Warn().Msgf("No ips found for %s, use direct ips: %v", apiDomain, apiIPs)
			ips = apiIPs
		}

		dial := func(ctx context.Context, network string, addrs []string) (net.Conn, error) {
			d := &ctrldnet.ParallelDialer{}
			logger := ctrld.LoggerFromCtx(loggerCtx)
			return d.DialContext(ctx, network, addrs, logger.Logger)
		}
		_, port, _ := net.SplitHostPort(addr)

		var attempts []error
		for _, stage := range apiDialStages(ips, apiIpsV4, apiIpsV6) {
			conn, err := dial(ctx, stage.network, addrsFromPort(stage.ips, port))
			if err == nil {
				return conn, nil
			}
			attempts = append(attempts, wrapAttempt(stage.what, err))
		}
		// Every attempt is reported, not just the last one. The stage that
		// diagnoses a local block is the IPv4 one - on Windows a firewall denying
		// ctrld's own socket surfaces there as WSAEACCES - while the last stage is
		// an IPv6 address that is commonly unroutable and fails with a bare "no
		// route to host". Returning only that turned a self-inflicted block into a
		// phantom routing problem and sent an incident investigation the wrong way.
		return nil, joinAttemptErrors(attempts)
	}
	if runtime.GOOS == "android" {
		transport.TLSClientConfig = &tls.Config{RootCAs: certs.CACertPool(), MinVersion: tls.VersionTLS12}
	}
	return transport
}

// apiDialStage is one attempt in the API transport's fallback order.
type apiDialStage struct {
	what    string
	network string
	ips     []string
}

// apiDialStages plans the dial order for one API connection: resolved IPv4, the
// direct IPv4, then the same for IPv6. The families are attempted separately
// because a host can have working connectivity to one and not the other.
//
// Every direct address is always dialed. It is the address that has to work when
// DNS does not, so it is dropped from its own stage only when it is already in
// the resolved list and the earlier stage therefore dials it anyway - dialing it
// twice doubles the failures without adding a chance of success. If resolution
// returns nothing, or returns addresses that are stale or wrong, the direct
// stages still carry the full direct list.
func apiDialStages(resolved, directV4, directV6 []string) []apiDialStage {
	// Different network stacks may have different connectivity to IPv4 vs IPv6.
	var ipv4s, ipv6s []string
	for _, ip := range resolved {
		if strings.Contains(ip, ":") {
			ipv6s = append(ipv6s, ip)
		} else {
			ipv4s = append(ipv4s, ip)
		}
	}
	stages := []apiDialStage{
		{"resolved ipv4", "tcp4", ipv4s},
		{"direct ipv4", "tcp4", notIn(directV4, ipv4s)},
		{"resolved ipv6", "tcp6", ipv6s},
		{"direct ipv6", "tcp6", notIn(directV6, ipv6s)},
	}
	out := make([]apiDialStage, 0, len(stages))
	for _, stage := range stages {
		if len(stage.ips) > 0 {
			out = append(out, stage)
		}
	}
	return out
}

// notIn returns the members of ips that are absent from seen.
//
// The direct-IP stages exist for when the hostname does not resolve, and LookupIP
// usually answers with those very addresses, so dialing both lists doubles the
// failures for no added chance of success.
func notIn(ips, seen []string) []string {
	if len(seen) == 0 {
		return ips
	}
	var out []string
	for _, ip := range ips {
		if !slices.Contains(seen, ip) {
			out = append(out, ip)
		}
	}
	return out
}

// wrapAttempt labels one dial attempt's failure with the stage that produced it,
// so a joined error says which family and which address list failed how.
func wrapAttempt(what string, err error) error {
	return fmt.Errorf("%s: %w", what, err)
}

// joinAttemptErrors combines the dial attempts into one error.
func joinAttemptErrors(attempts []error) error {
	switch len(attempts) {
	case 0:
		return errors.New("no api address to dial")
	case 1:
		return attempts[0]
	}
	return &dialAttemptsError{attempts: attempts}
}

// dialAttemptsError carries every attempt the API dialer made.
//
// errors.Join would do the same for errors.Is, but renders one attempt per line,
// and these end up in a single log record; this keeps them on one line. Unwrap
// returns all of them, so a caller testing for a specific errno - a local socket
// denial rather than an unroutable address - finds it wherever in the sequence it
// happened, not only if it happened last.
type dialAttemptsError struct {
	attempts []error
}

func (e *dialAttemptsError) Error() string {
	msgs := make([]string, 0, len(e.attempts))
	for _, err := range e.attempts {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// Unwrap exposes every attempt to errors.Is and errors.As.
func (e *dialAttemptsError) Unwrap() []error { return e.attempts }

func addrsFromPort(ips []string, port string) []string {
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = net.JoinHostPort(ip, port)
	}
	return addrs
}

// doWithFallback sends req, retrying against apiIp directly if the first attempt
// fails (typically because DNS is not usable yet).
//
// Both failures are reported. The first attempt carries the diagnosis - on Windows
// a local firewall denying the socket surfaces there as WSAEACCES ("An attempt was
// made to access a socket in a way forbidden by its access permissions"), which
// says the host is blocking ctrld rather than that the network is down. Returning
// only the fallback error hid that behind a bare "no route to host" from the IPv6
// attempt and sent the Firewall Mode incident investigation after a routing
// problem that did not exist.
func doWithFallback(ctx context.Context, client *http.Client, req *http.Request, apiIp string) (*http.Response, error) {
	resp, err := client.Do(req)
	if err == nil {
		return resp, nil
	}
	logger := ctrld.LoggerFromCtx(ctx)
	logger.Warn().Err(err).Msgf("Failed to send request, fallback to direct ip: %s", apiIp)
	ipReq := req.Clone(req.Context())
	ipReq.Host = apiIp
	ipReq.URL.Host = apiIp
	resp, fallbackErr := client.Do(ipReq)
	if fallbackErr != nil {
		return nil, fmt.Errorf("request failed: %w; fallback to direct ip %s failed: %w", err, apiIp, fallbackErr)
	}
	return resp, nil
}

// apiServerIP returns the direct IP to connect to API server.
func apiServerIP(cdDev bool) string {
	if cdDev {
		return apiDomainDevIPv4
	}
	return apiDomainComIPv4
}

// DoWithFallbackForTest exposes doWithFallback so tests outside this package can drive
// the real two-attempt composition through the real retry predicate, rather than
// asserting a copy of this error shape against another copy of it.
func DoWithFallbackForTest(ctx context.Context, client *http.Client, req *http.Request, apiIp string) (*http.Response, error) {
	return doWithFallback(ctx, client, req, apiIp)
}

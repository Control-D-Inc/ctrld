package cli

import (
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// AppCallback provides hooks for injecting certain functionalities
// from mobile platforms to main ctrld cli.
type AppCallback struct {
	HostName   func() string
	LanIp      func() string
	MacAddress func() string
	// Exit gets a failure line of the run. ctrld calls it before the run
	// ends, and the run does not end until Exit returns. So Exit must not
	// wait for the run to end: a wait with a timeout stalls the stop until
	// the timeout, and a wait with no timeout never ends.
	Exit func(error string)
}

// AppConfig allows overwriting ctrld cli flags from mobile platforms.
type AppConfig struct {
	CdUID          string
	ProvisionID    string
	CustomHostname string
	HomeDir        string
	UpstreamProto  string
	Verbose        int
	LogPath        string
	// Dev makes ctrld use the dev API, like the --dev flag.
	Dev bool
	// MemoryLimitMiB, if more than 0, is the Go memory limit of the process.
	MemoryLimitMiB int
	// Nameservers is a comma-separated list of the OS resolvers that the app
	// reports. If it is empty, ctrld finds the OS resolvers itself. Each start
	// replaces the list that SetMobileNameservers set before it.
	Nameservers string
}

// osResolverReasonAppNameservers marks an OS resolver read that the app
// started with SetMobileNameservers.
const osResolverReasonAppNameservers = "app_nameservers"

// setMemoryLimit is debug.SetMemoryLimit. Tests replace it.
var setMemoryLimit = debug.SetMemoryLimit

// applyAppConfig puts the values of appConfig into the CLI flag globals.
// The globals stay between runs in one process, so each input of a run is
// set on every run. cdUID is the exception: a token exchange sets it during
// a run, and the next run with the same token must use that UID. Without it,
// that run exchanges the token again and the API makes a new device.
func applyAppConfig(appConfig *AppConfig) {
	noConfigStart = false
	homedir = appConfig.HomeDir
	verbose = appConfig.Verbose
	cdOrg = appConfig.ProvisionID
	customHostname = appConfig.CustomHostname
	if appConfig.CdUID != "" {
		cdUID = appConfig.CdUID
	}
	storeLogSecrets()
	cdUpstreamProto = appConfig.UpstreamProto
	logPath = appConfig.LogPath
	cdDev = appConfig.Dev
	if appConfig.MemoryLimitMiB > 0 {
		setMemoryLimit(int64(appConfig.MemoryLimitMiB) << 20)
	}
	ctrld.SetAppNameservers(splitNameservers(appConfig.Nameservers))
}

// SetMobileNameservers makes the comma-separated list csv the OS resolvers,
// and builds the OS resolver again from them. The app calls it when the
// network of the device changes. It is safe to call while ctrld runs. A list
// with no IP address keeps the current OS resolver, because a device without
// a network reports no nameservers. The next start replaces the list with
// the nameservers of its AppConfig.
func SetMobileNameservers(csv string) {
	nss := ctrld.ParseNameservers(splitNameservers(csv))
	if len(nss) == 0 {
		return
	}
	ctrld.SetAppNameservers(nss)
	ctrld.InitializeOsResolverWithReason(true, osResolverReasonAppNameservers)
}

func splitNameservers(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	return strings.Split(csv, ",")
}

const (
	defaultHTTPTimeout = 30 * time.Second
	defaultMaxRetries  = 3
	downloadServerIp   = "23.171.240.151"
)

// httpClientWithFallback returns an HTTP client configured with timeout and IPv4 fallback
func httpClientWithFallback(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Prefer IPv4 over IPv6
			DialContext: (&net.Dialer{
				Timeout:       10 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 1 * time.Millisecond, // Very small delay to prefer IPv4
			}).DialContext,
		},
	}
}

// doWithRetry performs an HTTP request with retries
func doWithRetry(req *http.Request, maxRetries int, ip string) (*http.Response, error) {
	return doWithRetryClient(httpClientWithFallback(defaultHTTPTimeout), req, maxRetries, ip)
}

// doWithRetryClient is doWithRetry with an injectable client, so the retry and
// error-composition behaviour can be tested without real network access.
func doWithRetryClient(client *http.Client, req *http.Request, maxRetries int, ip string) (*http.Response, error) {
	var lastErr error
	var ipReq *http.Request
	if ip != "" {
		ipReq = req.Clone(req.Context())
		ipReq.Host = ip
		ipReq.URL.Host = ip
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second * time.Duration(attempt+1)) // Exponential backoff
		}

		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		// Keep the hostname attempt's error: it carries the diagnosis (on Windows,
		// a local firewall denying the socket shows up here as WSAEACCES), while the
		// direct-IP fallback often fails for an unrelated reason such as an
		// unreachable IPv6 route.
		attemptErr := err
		if ipReq != nil {
			mainLog.Load().Warn().Err(err).Msgf("dial to %q failed", req.Host)
			mainLog.Load().Warn().Msgf("fallback to direct IP to download prod version: %q", ip)
			resp, fallbackErr := client.Do(ipReq)
			if fallbackErr == nil {
				return resp, nil
			}
			attemptErr = fmt.Errorf("%w; fallback to direct ip %s failed: %w", attemptErr, ip, fallbackErr)
		}

		lastErr = attemptErr
		mainLog.Load().Debug().Err(attemptErr).
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Msgf("HTTP request attempt %d/%d failed", attempt+1, maxRetries)
	}
	return nil, fmt.Errorf("failed after %d attempts to %s %s: %w", maxRetries, req.Method, req.URL, lastErr)
}

// Helper for making GET requests with retries
func getWithRetry(url string, ip string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return doWithRetry(req, defaultMaxRetries, ip)
}

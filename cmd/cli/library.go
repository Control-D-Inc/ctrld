package cli

import (
	"context"
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
// This allows mobile applications to customize behavior without modifying core CLI code
type AppCallback struct {
	HostName   func() string
	LanIp      func() string
	MacAddress func() string
	// Exit gets a failure line of the run. An API preflight error at start,
	// or a deleted device during the run, gives a line with stage=api and the
	// HTTP status. The same line can come more than once in a run. ctrld
	// calls it before the run ends, and the run does not end until Exit
	// returns. So Exit must not wait for the run to end: a wait with a
	// timeout stalls the stop until the timeout, and a wait with no timeout
	// never ends.
	Exit func(error string)
}

// AppConfig allows overwriting ctrld cli flags from mobile platforms.
// This provides a clean interface for mobile apps to configure ctrld behavior
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
	storeJournalSecrets()
	cdUpstreamProto = appConfig.UpstreamProto
	logPath = appConfig.LogPath
	cdDev = appConfig.Dev
	if appConfig.MemoryLimitMiB > 0 {
		setMemoryLimit(int64(appConfig.MemoryLimitMiB) << 20)
	}
	// The log files open later in the run, so run logs the dropped values
	// with logDroppedStartNameservers. A log here reaches stdout only.
	startNameservers = appConfig.Nameservers
	ctrld.SetAppNameservers(context.Background(), splitNameservers(startNameservers))
}

// startNameservers is the Nameservers value of the current start.
var startNameservers string

// logDroppedStartNameservers logs each value of the nameservers of this start
// that is not an IP address. The app exports the log files, and the log is
// the only sign of the error that it gets.
func logDroppedStartNameservers(ctx context.Context) {
	ctrld.ParseNameservers(ctx, splitNameservers(startNameservers))
}

// SetMobileNameservers makes the comma-separated list csv the OS resolvers,
// and builds the OS resolver again from them. The app calls it when the
// network of the device changes. It is safe to call while ctrld runs. A list
// with no IP address keeps the current OS resolver, because a device without
// a network reports no nameservers. The next start replaces the list with
// the nameservers of its AppConfig.
func SetMobileNameservers(csv string) {
	ctx := appLoggerCtx()
	nss := ctrld.ParseNameservers(ctx, splitNameservers(csv))
	if len(nss) == 0 {
		return
	}
	ctrld.SetAppNameservers(ctx, nss)
	ctrld.InitializeOsResolverWithReason(ctx, true, osResolverReasonAppNameservers)
}

// appLoggerCtx carries the main logger to the root package, which logs the
// values of the app that are not IP addresses.
func appLoggerCtx() context.Context {
	return ctrld.LoggerCtx(context.Background(), mainLog.Load())
}

func splitNameservers(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	return strings.Split(csv, ",")
}

// Network and HTTP configuration constants
const (
	// defaultHTTPTimeout provides reasonable timeout for HTTP operations
	// This prevents hanging requests while allowing sufficient time for network delays
	defaultHTTPTimeout = 30 * time.Second

	// defaultMaxRetries provides retry attempts for failed HTTP requests
	// This improves reliability in unstable network conditions
	defaultMaxRetries = 3

	// downloadServerIp is the fallback IP for download operations
	// This ensures downloads work even when DNS resolution fails
	downloadServerIp = "23.171.240.151"
)

// httpClientWithFallback returns an HTTP client configured with timeout and IPv4 fallback
// This ensures reliable HTTP operations by preferring IPv4 and handling timeouts gracefully
func httpClientWithFallback(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Prefer IPv4 over IPv6
			// This improves compatibility with networks that have IPv6 issues
			DialContext: (&net.Dialer{
				Timeout:       10 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 1 * time.Millisecond, // Very small delay to prefer IPv4
			}).DialContext,
		},
	}
}

// doWithRetry performs an HTTP request with retries
// This improves reliability by automatically retrying failed requests with exponential backoff
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
			// Linear backoff reduces server load and improves success rate
			time.Sleep(time.Second * time.Duration(attempt+1))
		}

		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		// Keep the hostname attempt's error: it carries the diagnosis (on Windows,
		// a local firewall denying the socket shows up here as WSAEACCES), while the
		// direct-ip fallback often fails for an unrelated reason such as an
		// unreachable IPv6 route.
		attemptErr := err
		if ipReq != nil {
			mainLog.Load().Warn().Err(err).Msgf("Dial to %q failed", req.Host)
			mainLog.Load().Warn().Msgf("Fallback to direct ip to download prod version: %q", ip)
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
// This provides a simplified interface for common GET operations with built-in retry logic
func getWithRetry(url string, ip string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return doWithRetry(req, defaultMaxRetries, ip)
}

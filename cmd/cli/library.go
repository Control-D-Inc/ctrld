package cli

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// AppCallback provides hooks for injecting certain functionalities
// from mobile platforms to main ctrld cli.
// This allows mobile applications to customize behavior without modifying core CLI code
type AppCallback struct {
	HostName   func() string
	LanIp      func() string
	MacAddress func() string
	Exit       func(error string)
}

// AppConfig allows overwriting ctrld cli flags from mobile platforms.
// This provides a clean interface for mobile apps to configure ctrld behavior
type AppConfig struct {
	CdUID         string
	HomeDir       string
	UpstreamProto string
	Verbose       int
	LogPath       string
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
	var lastErr error
	client := httpClientWithFallback(defaultHTTPTimeout)
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
		if ipReq != nil {
			mainLog.Load().Warn().Err(err).Msgf("dial to %q failed", req.Host)
			mainLog.Load().Warn().Msgf("fallback to direct IP to download prod version: %q", ip)
			resp, err = client.Do(ipReq)
			if err == nil {
				return resp, nil
			}
		}

		lastErr = err
		mainLog.Load().Debug().Err(err).
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Msgf("HTTP request attempt %d/%d failed", attempt+1, maxRetries)
	}
	return nil, fmt.Errorf("failed after %d attempts to %s %s: %v", maxRetries, req.Method, req.URL, lastErr)
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

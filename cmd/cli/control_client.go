package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// controlClient represents an HTTP client for communicating with the control server
type controlClient struct {
	c *http.Client
}

// newControlClient creates a new control client with Unix socket transport
func newControlClient(addr string) *controlClient {
	return &controlClient{c: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "unix", addr)
			},
		},
		Timeout: time.Second * 30,
	}}
}

func (c *controlClient) post(path string, data io.Reader) (*http.Response, error) {
	// A log send uploads many megabytes, so it needs more time than the other
	// calls.
	if isSendLogsPath(path) {
		c.c.Timeout = time.Minute * 5
	}
	return c.c.Post("http://unix"+path, contentTypeJson, data)
}

// isSendLogsPath reports whether path addresses the log send handler. The path
// can carry a query, so the comparison takes the path alone. A path that does
// not parse keeps the prefix rule, because it still reaches that handler.
func isSendLogsPath(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return strings.HasPrefix(path, sendLogsPath)
	}
	return parsed.Path == sendLogsPath
}

// postStream sends a POST request with no timeout, suitable for long-lived streaming connections.
func (c *controlClient) postStream(path string, data io.Reader) (*http.Response, error) {
	c.c.Timeout = 0
	return c.c.Post("http://unix"+path, contentTypeJson, data)
}

// deactivationRequest represents request for validating deactivation pin.
type deactivationRequest struct {
	Pin int64 `json:"pin"`
}

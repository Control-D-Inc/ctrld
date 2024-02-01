package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

type controlClient struct {
	c *http.Client
}

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
	return c.c.Post("http://unix"+path, contentTypeJson, data)
}

// deactivationRequest represents request for validating deactivation pin.
type deactivationRequest struct {
	Pin int64 `json:"pin"`
}

package certs

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestCACertPool(t *testing.T) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: CACertPool(),
			},
		},
		Timeout: 2 * time.Second,
	}
	resp, err := c.Get("https://freedns.controld.com/p1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !resp.TLS.HandshakeComplete {
		t.Error("TLS handshake is not complete")
	}
}

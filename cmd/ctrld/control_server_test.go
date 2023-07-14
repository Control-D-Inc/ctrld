package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestControlServer(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	s, err := newControlServer(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	pattern := "/ping"
	respBody := []byte("pong")
	s.register(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(respBody)
	}))
	if err := s.start(); err != nil {
		t.Fatal(err)
	}

	c := newControlClient(f.Name())
	resp, err := c.post(pattern, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unepxected response code: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("content-type"); ct != contentTypeJson {
		t.Fatalf("unexpected content type: %s", ct)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, respBody) {
		t.Errorf("unexpected response body, want: %q, got: %q", string(respBody), string(buf))
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
}

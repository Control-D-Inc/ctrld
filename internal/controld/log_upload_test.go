package controld

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoWithFallbackResendsTheSpooledBody drives the two-attempt upload: the
// first attempt fails on a closed port and the fallback to the direct IP must
// carry the whole body, which the first attempt consumed.
func TestDoWithFallbackResendsTheSpooledBody(t *testing.T) {
	payload := strings.Repeat("log line\n", 4096)
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body, size, getBody, cleanup, err := spoolLogBody(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("spoolLogBody: %v", err)
	}
	defer cleanup()
	if size != int64(len(payload)) {
		t.Fatalf("size = %d, want %d", size, len(payload))
	}
	// Port 1 refuses the connection, so the first attempt fails at once.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://127.0.0.1:1/logs", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = size
	req.GetBody = getBody

	resp, err := doWithFallback(context.Background(), srv.Client(), req, strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("doWithFallback: %v", err)
	}
	resp.Body.Close()
	if got != payload {
		t.Fatalf("the fallback carried %d bytes, want %d", len(got), len(payload))
	}
}

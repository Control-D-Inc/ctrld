package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// streamRecorder collects a streamed response under a lock, because the
// handler writes from its own goroutine while the test reads.
type streamRecorder struct {
	mu     sync.Mutex
	header http.Header
	body   strings.Builder
}

func (r *streamRecorder) Header() http.Header { return r.header }

func (r *streamRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.Write(p)
}

func (r *streamRecorder) WriteHeader(int) {}

func (r *streamRecorder) Flush() {}

func (r *streamRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

// waitForText polls the recorder until want arrives or the deadline passes.
func waitForText(rec *streamRecorder, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), want) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Test_logTailFollowsTheRotatedLogPath keeps one tail request open while the
// log_path file rotates. The lines after the rotation must reach the client.
func Test_logTailFollowsTheRotatedLogPath(t *testing.T) {
	origUID := cdUID
	cdUID = ""
	t.Cleanup(func() { cdUID = origUID })

	path := filepath.Join(t.TempDir(), "ctrld.log")
	rf, err := newRotatingFile(path, logBudget{maxSize: 64, backups: 1}, nil)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rf.close() })
	if _, err := rf.Write([]byte("before rotation\n")); err != nil {
		t.Fatal(err)
	}

	p := &prog{
		cfg: &ctrld.Config{Service: ctrld.ServiceConfig{LogPath: path}},
		cs:  &controlServer{mux: http.NewServeMux()},
	}
	p.registerControlServerHandler()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, tailLogsPath+"?lines=1", nil).WithContext(ctx)
	rec := &streamRecorder{header: http.Header{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.cs.mux.ServeHTTP(rec, req)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if !waitForText(rec, "before rotation", 2*time.Second) {
		t.Fatalf("the first line did not arrive: %q", rec.String())
	}
	for i := 0; i < 4; i++ {
		if _, err := rf.Write([]byte("filler line that crosses the budget\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rf.Write([]byte("after rotation sentinel\n")); err != nil {
		t.Fatal(err)
	}
	if !waitForText(rec, "after rotation sentinel", 3*time.Second) {
		t.Fatalf("the sentinel did not arrive after the rotation: %q", rec.String())
	}
}

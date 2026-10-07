package cli

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// logUploadGate is shared by both sockets. Reserve before opening or collecting
// anything, and cool down after completion, including failures. Logging reloads
// must never reset this state.
type logUploadGate struct {
	mu   sync.Mutex
	busy bool
	next time.Time
}

func (g *logUploadGate) reserve() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy || time.Now().Before(g.next) {
		return false
	}
	g.busy = true
	return true
}

func (g *logUploadGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.busy = false
	g.next = time.Now().Add(logWriterSentInterval)
}

const delegatedSendTimeout = 5 * time.Minute

type logSendPeerKey struct{}

// logSendServer has no administrative mux. Its dependencies are immutable
// snapshots of daemon state, never request arguments or reloaded config pointers.
type logSendServer struct {
	gate    *logUploadGate
	collect func(context.Context) (io.ReadCloser, error)
	upload  func(context.Context, io.ReadCloser) error
	audit   func(int64, int)
	server  *http.Server
	cancel  context.CancelFunc
	mu      sync.Mutex
	stopped bool
	active  sync.WaitGroup
}

func (s *logSendServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uid, known := r.Context().Value(logSendPeerKey{}).(uint32)
	caller := int64(-1)
	if known {
		caller = int64(uid)
	}
	code := http.StatusForbidden
	accepted := false
	admitted := false
	defer func() {
		if admitted {
			defer s.active.Done()
		}
		if accepted && s.audit != nil {
			s.audit(caller, code)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		w.WriteHeader(code) // status only: no logs, credentials, paths or API errors
	}()
	if !known {
		return
	}
	if r.Method != http.MethodPost || r.RequestURI != sendLogsPath || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Expect") != "" {
		code = http.StatusBadRequest
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		code = http.StatusServiceUnavailable
		return
	}
	s.active.Add(1)
	admitted = true
	s.mu.Unlock()
	if !s.gate.reserve() {
		code = http.StatusServiceUnavailable
		return
	}
	accepted = true
	defer s.gate.release()
	ctx, cancel := context.WithTimeout(r.Context(), delegatedSendTimeout)
	defer cancel()
	body, err := s.collect(ctx)
	if err != nil {
		code = http.StatusPreconditionFailed
		return
	}
	defer body.Close()
	if err := s.upload(ctx, body); err != nil {
		code = http.StatusBadGateway
		return
	}
	code = http.StatusOK
}

func (s *logSendServer) stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.server != nil {
		_ = s.server.Close()
	}
	s.active.Wait()
}

// The lifecycle lock also covers startup racing with shutdown. Stop fences new
// requests, cancels active uploads, and joins them before log writers close.
func (p *prog) stopLogSendServer() {
	p.logSendMu.Lock()
	defer p.logSendMu.Unlock()
	p.logSendStopped = true
	if p.logSend != nil {
		p.logSend.stop()
	}
}

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// A handler that waits must end when the control server stops, and the client
// must not get a 200 from the stopped server: upgrade and restart take a 200
// from /started as "the new binary is ready". A handler that only returns
// still sends 200, so the handlers that have no other answer abort.
func TestControlServerStopEndsWaitingHandlers(t *testing.T) {
	tests := []struct {
		name string
		path string
		// hold makes a prog whose handler for path waits. It returns a
		// channel that closes once the handler waits, or nil when the start
		// of the handler is enough.
		hold func(t *testing.T) (*prog, <-chan struct{})
		// wantStatus is the status the client gets, or 0 for no answer.
		wantStatus int
	}{
		{name: "started", path: startedPath, hold: holdStarted},
		{name: "reload", path: reloadPath, hold: holdReload},
		{name: "iface", path: ifacePath, hold: holdIface},
		{name: "log send", path: sendLogsPath, hold: holdLogSend, wantStatus: http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, waiting := tc.hold(t)
			requireStopEndsHandler(t, p, tc.path, waiting, tc.wantStatus)
		})
	}
}

// requireStopEndsHandler serves the handlers of p, sends a request to path,
// and stops the server once the handler waits. waiting closes once the handler
// waits; nil means that the start of the handler is enough. The handler must
// end, and the client must get wantStatus, or no answer when it is 0.
func requireStopEndsHandler(t *testing.T, p *prog, path string, waiting <-chan struct{}, wantStatus int) {
	t.Helper()
	_, sock, cs := newTestControlServer(t)
	p.cs = cs
	p.registerControlServerHandler()
	entered, exited := make(chan struct{}), make(chan struct{})
	handlers := cs.server.Handler
	cs.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(exited)
		close(entered)
		handlers.ServeHTTP(w, r)
	})
	require.NoError(t, cs.start())
	if waiting == nil {
		waiting = entered
	}

	type answer struct {
		status int
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		resp, err := newControlClient(sock).post(path, nil)
		if err != nil {
			answered <- answer{err: err}
			return
		}
		resp.Body.Close()
		answered <- answer{status: resp.StatusCode}
	}()

	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never reached its wait")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- cs.stop() }()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler still waits after the control server stopped")
	}
	require.NoError(t, <-stopped, "the stop did not see the handler end")

	var got answer
	select {
	case got = <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("the client got no end to its request")
	}
	if wantStatus == 0 {
		require.Error(t, got.err, "the stopped control server answered %d", got.status)
		return
	}
	require.NoError(t, got.err)
	require.Equal(t, wantStatus, got.status)
}

// A run that is ready when the server stops must not answer /started either.
// The wait then has two cases ready, and select picks one at random, so the
// test asks many times.
func TestStoppedControlServerDoesNotAnswerStartedOfReadyRun(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	_, _, cs := newTestControlServer(t)
	p := &prog{cs: cs, onStartedDone: ready}
	p.registerControlServerHandler()
	stopped, stop := context.WithCancel(context.Background())
	stop()

	for range 32 {
		request := httptest.NewRequestWithContext(stopped, http.MethodPost, startedPath, nil)
		require.PanicsWithValue(t, http.ErrAbortHandler, func() {
			cs.mux.ServeHTTP(httptest.NewRecorder(), request)
		}, "a stopped control server answered /started")
	}
}

// A ready run of a live control server answers /started with 200, the answer
// that upgrade and restart wait for.
func TestControlServerAnswersStartedOfReadyRun(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	_, sock, cs := newTestControlServer(t)
	p := &prog{cs: cs, onStartedDone: ready}
	p.registerControlServerHandler()
	require.NoError(t, cs.start())

	resp, err := newControlClient(sock).post(startedPath, nil)

	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// holdStarted keeps the run not ready, so /started waits for it.
func holdStarted(t *testing.T) (*prog, <-chan struct{}) {
	ready := make(chan struct{})
	t.Cleanup(func() { close(ready) })
	return &prog{onStartedDone: ready}, nil
}

// holdReload sends the reload signal to nobody that reloads, so /reload waits
// for the end of the reload. The test catches the signal to learn that the
// handler sent it, and the handler then waits. The buffered reloadCh takes the
// send on Windows; the Windows test of a send that waits is separate.
func holdReload(t *testing.T) (*prog, <-chan struct{}) {
	signals := make(chan os.Signal, 1)
	notifyReloadSigCh(signals)
	t.Cleanup(func() { stopNotifyReloadSigCh(signals) })
	p := &prog{
		cfg:          &ctrld.Config{},
		reloadDoneCh: make(chan struct{}),
		reloadCh:     make(chan struct{}, 1),
	}
	waiting := make(chan struct{})
	go func() {
		select {
		case <-signals:
		case <-p.reloadCh:
		}
		close(waiting)
	}()
	return p, waiting
}

// holdIface runs as the service before the DNS is set, so /iface waits for
// the DNS setup.
func holdIface(t *testing.T) (*prog, <-chan struct{}) {
	oldRunningAsService := runningAsService
	runningAsService = func() bool { return true }
	dnsSet := make(chan struct{}, 1)
	t.Cleanup(func() {
		close(dnsSet)
		runningAsService = oldRunningAsService
	})
	return &prog{cfg: &ctrld.Config{}, csSetDnsDone: dnsSet}, nil
}

// holdLogSend holds the upload until its context ends. The handler waits
// once the upload starts.
func holdLogSend(t *testing.T) (*prog, <-chan struct{}) {
	p := setupMemoryLogReaderTest(t)
	_, err := p.internalLogWriter.Write([]byte("a log line\n"))
	require.NoError(t, err)

	uploading, released := make(chan struct{}), make(chan struct{})
	oldSendLogs := sendLogsToAPI
	sendLogsToAPI = func(ctx context.Context, req *controld.LogsRequest, _ bool) error {
		defer req.Data.Close()
		close(uploading)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-released:
			return nil
		}
	}
	t.Cleanup(func() {
		close(released)
		sendLogsToAPI = oldSendLogs
	})
	return p, uploading
}

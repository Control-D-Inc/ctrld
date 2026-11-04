package cli

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kardianos/service"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// A stopping process must not answer /started for the service that replaces
// it. `ctrld upgrade` treats any reply as "the new binary is up", so a reply
// from the old process, while it waits for its components to stop, turned an
// upgrade to a never-ready build into "Upgrade successful" instead of a
// rollback (ctrld-qa upgrade-readiness-rollback on v1.0).
func TestStopClosesControlServerBeforeRunFinishes(t *testing.T) {
	// A short path, as the other control server tests use: t.TempDir() is
	// longer than a Unix socket path may be.
	f, err := os.CreateTemp("", "")
	require.NoError(t, err)
	sock := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(sock) })
	cs, err := newControlServer(sock)
	require.NoError(t, err)
	cs.register(startedPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	require.NoError(t, cs.start())

	p := &prog{
		cfg:    &ctrld.Config{},
		cs:     cs,
		waitCh: make(chan struct{}), stopCh: make(chan struct{}), runDone: make(chan struct{}),
		runAbortCh: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}),
		pinCodeValidCh: make(chan struct{}, 1),
	}
	p.logger.Store(mainLog.Load())
	p.pinCodeValidCh <- struct{}{} // accept the stop even if a deactivation pin is configured

	cc := newControlClient(sock)
	resp, err := cc.post(startedPath, nil)
	require.NoError(t, err, "the running service answers")
	resp.Body.Close()

	require.NoError(t, p.Stop(nil))
	// runDone is still open: the run has not finished, as when a component is
	// slow to stop. The socket must already be closed.
	_, err = cc.post(startedPath, nil)
	require.Error(t, err, "a stopped service answered /started")

	p.stopControlServer() // the later releaseResources call is harmless
}

// startTestControlServer starts a control server on a short socket path in a
// directory of its own, as the socket client expects, answering /started with
// whatever started returns.
func startTestControlServer(t *testing.T, started func() int) (dir, sock string, cs *controlServer) {
	t.Helper()
	// A short path, as the other control server tests use: t.TempDir() is
	// longer than a Unix socket path may be.
	dir, err := os.MkdirTemp("", "cs")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, ctrldControlUnixSock)
	cs, err = newControlServer(sock)
	require.NoError(t, err)
	cs.register(startedPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(started()) }))
	cs.register(listClientsPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	require.NoError(t, cs.start())
	t.Cleanup(func() { _ = cs.stop() })
	// start serves on a goroutine, and the server tracks the listener only
	// once that runs: a Shutdown before then leaves the listener, and its
	// unlink, to Serve's own deferred close. Wait until it answers, as a
	// service that has been running does. A path other than /started keeps
	// the started func's call count to the test's own requests.
	require.Eventually(t, func() bool {
		resp, err := newControlClient(sock).post(listClientsPath, nil)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "control server did not start serving")
	return dir, sock, cs
}

// Stop unlinks the socket path as it closes the socket, before the successor
// starts: unlinking it later removed the path the successor had bound.
func TestStopRemovesControlSocketPath(t *testing.T) {
	_, sock, cs := startTestControlServer(t, func() int { return http.StatusOK })
	p := &prog{
		cfg:    &ctrld.Config{},
		cs:     cs,
		waitCh: make(chan struct{}), stopCh: make(chan struct{}), runDone: make(chan struct{}),
		runAbortCh: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}),
		pinCodeValidCh: make(chan struct{}, 1),
	}
	p.logger.Store(mainLog.Load())
	p.pinCodeValidCh <- struct{}{}

	require.NoError(t, p.Stop(nil))
	_, err := os.Stat(sock)
	require.True(t, os.IsNotExist(err), "socket path still present after Stop: %v", err)
}

// A stop path that never calls Stop still closes the control server.
func TestReleaseResourcesClosesControlServer(t *testing.T) {
	_, sock, cs := startTestControlServer(t, func() int { return http.StatusOK })
	p := &prog{cfg: &ctrld.Config{}, cs: cs}
	p.logger.Store(mainLog.Load())

	p.releaseResources()
	_, err := newControlClient(sock).post(startedPath, nil)
	require.Error(t, err, "the control server answered after releaseResources")
}

// `ctrld upgrade` must not count a successor that started but never became
// ready: it answers /started with 408, and only a 200 means ready. The plain
// socket client keeps accepting any answer, because the deactivation pin check
// must reach a running service whether or not it is ready.
func TestReadySocketControlClientRequiresReady(t *testing.T) {
	running := &fakeService{statuses: []service.Status{service.StatusRunning}}

	t.Run("never ready", func(t *testing.T) {
		dir, _, _ := startTestControlServer(t, func() int { return http.StatusRequestTimeout })
		require.Nil(t, newReadySocketControlClientWithTimeout(context.Background(), running, dir, 2*time.Second),
			"a service answering 408 counted as ready")
		require.NotNil(t, newSocketControlClientWithTimeout(context.Background(), running, dir, 2*time.Second),
			"the plain client must still reach a running service that is not ready")
	})

	t.Run("becomes ready", func(t *testing.T) {
		var calls atomic.Int32
		dir, _, _ := startTestControlServer(t, func() int {
			if calls.Add(1) == 1 {
				return http.StatusRequestTimeout
			}
			return http.StatusOK
		})
		require.NotNil(t, dialSocketControlServer(context.Background(), running, dir, 10*time.Second, true),
			"the poll gave up on a service that became ready")
		require.GreaterOrEqual(t, calls.Load(), int32(2), "the poll stopped at the 408")
	})
}

package cli

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

func TestRunWaitStopsBeforeStartup(t *testing.T) {
	p := &prog{
		waitCh:  make(chan struct{}),
		stopCh:  make(chan struct{}),
		runDone: make(chan struct{}),
	}
	p.logger.Store(mainLog.Load())
	require.NoError(t, p.Start(nil))
	close(p.stopCh)
	select {
	case <-p.runDone:
	case <-time.After(time.Second):
		t.Fatal("stop did not terminate workers waiting for startup")
	}
}

func TestRunDoesNotStartAfterStop(t *testing.T) {
	for i := 0; i < 100; i++ {
		p := &prog{waitCh: make(chan struct{}), stopCh: make(chan struct{})}
		p.logger.Store(mainLog.Load())
		close(p.waitCh)
		close(p.stopCh)
		// cfg is deliberately nil: reaching component startup is a failure.
		p.run(false, make(chan struct{}))
	}
}

func TestRunMobilePreflightCleanup(t *testing.T) {
	const childEnv = "CTRLD_TEST_MOBILE_PREFLIGHT"
	mode := os.Getenv(childEnv)
	if mode == "" {
		for _, mode := range []string{"stop", "failure"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunMobilePreflightCleanup$", "-test.v")
				cmd.Env = append(os.Environ(), childEnv+"="+mode)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
			})
		}
		return
	}

	// Keep the real RunMobile -> run -> Start -> runWait path, but replace the
	// platform cleanup and API boundaries before any host setup can happen.
	isMobile = func() bool { return true }
	networkUp = func() bool { return true }
	cleanupCalls := 0
	cleanupStaleDNSInterceptStateFn = func() { cleanupCalls++ }
	dir := t.TempDir()
	configPath = filepath.Join(dir, "ctrld.toml")
	require.NoError(t, os.WriteFile(configPath, []byte("[service]\n"), 0600))
	want := errors.New("preflight rejected")
	for i := 0; i < 3; i++ {
		stopCh := make(chan struct{})
		fetchCalls, exits := 0, 0
		processCDFlagsFn = func(ctx context.Context, _ *ctrld.Config) (*controld.ResolverConfig, error) {
			fetchCalls++
			require.Eventually(t, startupWorkersRunning, time.Second, time.Millisecond)
			if mode == "stop" {
				close(stopCh)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, want
		}
		callback := AppCallback{Exit: func(err string) {
			exits++
			require.Equal(t, want.Error(), err)
		}}
		RunMobile(&AppConfig{CdUID: "testuid", HomeDir: dir, UpstreamProto: "doh", LogPath: filepath.Join(dir, "ctrld.log")}, &callback, stopCh)
		require.Equal(t, 1, fetchCalls)
		if mode == "failure" {
			require.Equal(t, 1, exits)
			require.False(t, stopRequested(stopCh), "cleanup must not close the controller-owned channel")

		} else {
			require.Zero(t, exits)
		}
		require.False(t, startupWorkersRunning(), "RunMobile returned before its workers stopped")
		if mode == "failure" {
			close(stopCh) // A later Controller.Stop must remain safe.
		}
	}
	require.Equal(t, 3, cleanupCalls, "the real stale intercept cleanup must never be reached")
}

func startupWorkersRunning() bool {
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	return strings.Contains(string(stack[:n]), "(*prog).runWait(") || strings.Contains(string(stack[:n]), "(*prog).run(")
}

func TestControlServerStopOnlyUnlinksOwnedListener(t *testing.T) {
	// Keep the Unix socket path below macOS's limit, including its long TMPDIR.
	dir, err := os.MkdirTemp("", "ctrld-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	owner, err := newControlServer(path)
	require.NoError(t, err)
	require.NoError(t, owner.start())
	t.Cleanup(func() { _ = owner.stop() })
	unstarted, err := newControlServer(path)
	require.NoError(t, err)
	require.NoError(t, unstarted.stop())
	c, err := net.Dial("unix", path)
	require.NoError(t, err, "stopping before startup must preserve someone else's socket")
	require.NoError(t, c.SetDeadline(time.Now().Add(time.Second)))
	_, err = io.WriteString(c, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, c.Close())
	require.NoError(t, owner.stop())
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err), "owned socket must be unlinked on shutdown: %v", err)
}

func TestShutdownClosesStartupLogConnection(t *testing.T) {
	c, peer := net.Pipe()
	defer peer.Close()
	p := &prog{cfg: &ctrld.Config{}, dnsWatcherStopCh: make(chan struct{}), logConn: c}
	p.logger.Store(mainLog.Load())
	require.NoError(t, p.shutdown())
	require.NoError(t, p.shutdown())
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := peer.Write([]byte("x"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

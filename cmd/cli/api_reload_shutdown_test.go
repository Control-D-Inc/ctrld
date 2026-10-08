package cli

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

func TestAPIConfigReloadShutdown(t *testing.T) {
	const env = "CTRLD_TEST_API_RELOAD_SHUTDOWN"
	mode := os.Getenv(env)
	if mode == "" {
		for _, mode := range []string{"stop-exclude", "abort-exclude", "stop-custom", "abort-custom", "stop-internal", "abort-internal", "stop-fetch", "abort-fetch", "live-exclude", "live-custom", "live-internal"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAPIConfigReloadShutdown$", "-test.v")
				cmd.Env = append(os.Environ(), env+"="+mode)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
			})
		}
		return
	}
	cdUID = "testuid"
	version = "dev"
	p := &prog{
		cfg: &ctrld.Config{}, rc: &controld.ResolverConfig{},
		stopCh: make(chan struct{}), runAbortCh: make(chan struct{}),
		apiForceReloadCh: make(chan struct{}), apiReloadCh: make(chan *ctrld.Config),
	}
	p.logger.Store(mainLog.Load())
	rc := &controld.ResolverConfig{Exclude: []string{"internal.test"}}
	if strings.HasSuffix(mode, "internal") {
		rc.Exclude = nil
		rc.SplitDNS = []controld.SplitDNS{{Domain: "internal.test", Mode: controld.SplitDNSModeOS}}
	}
	if strings.HasSuffix(mode, "custom") {
		rc.Ctrld.CustomConfig = base64.StdEncoding.EncodeToString([]byte(`[listener.0]
ip = "127.0.0.1"
port = 5354
[network.0]
cidrs = ["127.0.0.0/8"]
[upstream.0]
type = "legacy"
endpoint = "127.0.0.1"
`))
	}
	entered, canceled := make(chan struct{}), make(chan struct{})
	fetchResolverConfigFn = func(ctx context.Context, _ *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
		close(entered)
		if strings.HasSuffix(mode, "fetch") {
			<-ctx.Done()
			close(canceled)
			// A late successful response must not schedule a reload after stop.
			return rc, nil
		}
		return rc, nil
	}
	done := make(chan struct{})
	go func() { p.apiConfigReload(); close(done) }()
	p.apiForceReloadCh <- struct{}{}
	awaitShutdown(t, entered)
	if strings.HasPrefix(mode, "live-") {
		select {
		case got := <-p.apiReloadCh:
			if strings.HasSuffix(mode, "custom") {
				require.NotNil(t, got)
				require.Equal(t, "127.0.0.1", got.Listener["0"].IP)
			} else {
				require.Nil(t, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("running API loop did not deliver its reload")
		}
	} else if !strings.HasSuffix(mode, "fetch") {
		marker := "Exclude list changes detected, reloading"
		if strings.HasSuffix(mode, "custom") {
			marker = "Custom config changes detected, reloading"
		} else if strings.HasSuffix(mode, "internal") {
			marker = "Internal domain changes detected, reloading"
		}
		require.Eventually(t, func() bool { return strings.Contains(logOutput.String(), marker) }, time.Second, time.Millisecond)
	}
	if strings.HasPrefix(mode, "abort-") {
		close(p.runAbortCh)
	} else {
		close(p.stopCh)
	}
	awaitShutdown(t, done)
	if strings.HasSuffix(mode, "fetch") {
		awaitShutdown(t, canceled)
		require.Empty(t, p.rc.Exclude, "late fetch must not update run state")
	}
}

func TestForceFetchingAPIStopsWithoutReceiver(t *testing.T) {
	old := cdUID
	cdUID = "testuid"
	t.Cleanup(func() { cdUID = old })
	for _, abort := range []bool{false, true} {
		for _, delivered := range []bool{false, true} {
			p := &prog{cfg: &ctrld.Config{}, stopCh: make(chan struct{}), runAbortCh: make(chan struct{}), apiForceReloadCh: make(chan struct{})}
			p.logger.Store(mainLog.Load())
			p.forceFetchingAPI("testuid.verify.controld.com")
			done := p.apiForceReloadGroup.DoChan("force_sync_api", func() (interface{}, error) { t.Error("lost active force-reload worker"); return nil, nil })
			if delivered {
				select {
				case <-p.apiForceReloadCh:
				case <-time.After(time.Second):
					t.Fatal("no force-reload signal")
				}
			}
			if abort {
				close(p.runAbortCh)
			} else {
				close(p.stopCh)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("force-reload send/cooldown survived stop")
			}
		}
	}
}

type closeCountingLogConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingLogConn) Close() error              { c.closes.Add(1); return nil }
func (*closeCountingLogConn) Write(b []byte) (int, error) { return len(b), nil }

func TestStartupLogConnectionCloseOwnership(t *testing.T) {
	c := &closeCountingLogConn{}
	p := &prog{cfg: &ctrld.Config{}, dnsWatcherStopCh: make(chan struct{}), logConn: c}
	p.logger.Store(mainLog.Load())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.notifyExitToLogServer(); p.closeLogConn() }()
	}
	wg.Wait()
	require.NoError(t, p.shutdown())
	require.EqualValues(t, 1, c.closes.Load())
	require.Nil(t, p.logConn)
}

package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// TestRunMobileReportsProvisionFailure drives the real RunMobile -> run path
// on mobile for each kind of failProvision caller: the host app must get one
// Exit carrying the failure, ctrld must never exit the process, and nothing
// may be left for the next run. Each case runs in its own process because
// run() leaves package state behind.
func TestRunMobileReportsProvisionFailure(t *testing.T) {
	const childEnv = "CTRLD_TEST_MOBILE_PROVISION_FAILURE"
	mode := os.Getenv(childEnv)
	if mode == "" {
		for _, mode := range []string{"token-shape", "listener-bind", "network-down", "proto-then-valid", "stale"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunMobileReportsProvisionFailure$", "-test.v")
				cmd.Env = append(os.Environ(), childEnv+"="+mode)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
			})
		}
		return
	}

	isMobile = func() bool { return true }
	networkUp = func() bool { return true }
	// Never reach the real stale intercept cleanup on the test host.
	cleanupStaleDNSInterceptStateFn = func() {}
	provisionExit = func(code int) { t.Fatalf("process exit %d on mobile", code) }
	dir := t.TempDir()
	configPath = filepath.Join(dir, "ctrld.toml")
	require.NoError(t, os.WriteFile(configPath, []byte("[service]\n"), 0600))
	fetches := 0
	processCDFlagsFn = func(context.Context, *ctrld.Config) (*controld.ResolverConfig, error) {
		fetches++
		return nil, errors.New("preflight rejected")
	}
	var exits []string
	callback := AppCallback{Exit: func(err string) { exits = append(exits, err) }}
	appConfig := func(c AppConfig) *AppConfig {
		c.HomeDir = dir
		c.LogPath = filepath.Join(dir, "ctrld.log")
		if c.UpstreamProto == "" {
			c.UpstreamProto = "doh"
		}
		return &c
	}
	runOnce := func(c AppConfig) {
		stopCh := make(chan struct{})
		RunMobile(appConfig(c), &callback, stopCh)
		require.False(t, stopRequested(stopCh), "run must not close the controller-owned channel")
		require.Nil(t, pendingProvisionFailure.Load(), "a failure was left for the next run")
	}
	wantExit := func(code provisionFailureCode) {
		t.Helper()
		r := newProvisionResult(code, "", nil)
		require.Equal(t, []string{r.failureLine()}, exits)
		exits = nil
	}

	switch mode {
	case "token-shape":
		runOnce(AppConfig{ProvisionID: "not a token"})
		wantExit(provisionCodeProvisionTokenMalformed)
		require.Zero(t, fetches)
	case "listener-bind":
		// Hold the configured address so the listener cannot bind it.
		held, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer held.Close()
		port := held.LocalAddr().(*net.UDPAddr).Port
		require.NoError(t, os.WriteFile(configPath, []byte("[service]\n[listener.0]\nip = \"127.0.0.1\"\nport = "+strconv.Itoa(port)+"\n"), 0600))
		runOnce(AppConfig{})
		wantExit(provisionCodeListenerAddrUnavail)
	case "network-down":
		networkUp = func() bool { return false }
		runOnce(AppConfig{CdUID: "testuid"})
		wantExit(provisionCodeUnclassified)
		require.Zero(t, fetches)
	case "proto-then-valid":
		runOnce(AppConfig{CdUID: "testuid", UpstreamProto: "dot"})
		wantExit(provisionCodeInvalidFlagCombination)
		require.Zero(t, fetches)
		// The next start must reach the API instead of replaying that failure.
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		require.Equal(t, []string{"preflight rejected"}, exits)
	case "stale":
		// A failure recorded outside any run must not abort the next one.
		pendingProvisionFailure.Store(newProvisionResult(provisionCodeUnclassified, "stale", nil))
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		require.Equal(t, []string{"preflight rejected"}, exits)
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

// TestReportServeDNSFailureMobile covers the listener goroutine that fails
// after startup: on mobile it cannot exit, so it must hand the failure to the
// host app straight away.
func TestReportServeDNSFailureMobile(t *testing.T) {
	stubProvisionGlobals(t)
	oldIsMobile := isMobile
	t.Cleanup(func() { isMobile = oldIsMobile; pendingProvisionFailure.Store(nil) })
	isMobile = func() bool { return true }
	provisionExit = func(code int) { t.Fatalf("process exit %d on mobile", code) }
	var exits []string
	p := &prog{appCallback: &AppCallback{Exit: func(err string) { exits = append(exits, err) }}}
	p.logger.Store(mainLog.Load())

	p.reportServeDNSFailure("0", errors.New("serve failed"))

	require.Equal(t, []string{newProvisionResult(provisionCodeUnclassified, "", nil).failureLine()}, exits)
	require.Nil(t, pendingProvisionFailure.Load())
}

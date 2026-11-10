package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/mobile"
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
		for _, mode := range []string{"token-shape", "listener-bind", "network-down", "network-stop", "proto-then-valid", "stale", "api-error-secret", "no-host-tools", "token-exchange-redacts", "start-nameservers-logged", "console-level"} {
			t.Run(mode, func(t *testing.T) {
				if mode == "no-host-tools" && runtime.GOOS != "darwin" {
					t.Skip("the fake tools are the tools of macOS and iOS")
				}
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
	networkUp = func(<-chan struct{}) bool { return true }
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
		networkUp = func(<-chan struct{}) bool { return false }
		runOnce(AppConfig{CdUID: "testuid"})
		wantExit(provisionCodeUnclassified)
		require.Zero(t, fetches)
	case "network-stop":
		// A stop while the network is down is a normal stop, not a failure.
		networkUp = func(stop <-chan struct{}) bool { <-stop; return false }
		stopCh := make(chan struct{})
		close(stopCh)
		RunMobile(appConfig(AppConfig{CdUID: "testuid"}), &callback, stopCh)
		require.Empty(t, exits)
		require.Zero(t, fetches)
	case "proto-then-valid":
		runOnce(AppConfig{CdUID: "testuid", UpstreamProto: "dot"})
		wantExit(provisionCodeInvalidFlagCombination)
		require.Zero(t, fetches)
		// The next start must reach the API instead of replaying that failure.
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		require.Equal(t, []string{"provisioning failed: stage=api code=API_UNREACHABLE (exit 30)"}, exits)
	case "stale":
		// A failure recorded outside any run must not abort the next one.
		pendingProvisionFailure.Store(newProvisionResult(provisionCodeUnclassified, "stale", nil))
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		require.Equal(t, []string{"provisioning failed: stage=api code=API_UNREACHABLE (exit 30)"}, exits)
	case "api-error-secret":
		// The API can echo the request back, so its error text reaches the
		// app only as a code.
		const uid = "1e0rkx9a7tq"
		processCDFlagsFn = func(context.Context, *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			resp := &controld.ErrorResponse{StatusCode: 404}
			resp.ErrorField.Message = "resolver " + uid + " not found"
			return nil, resp
		}
		runOnce(AppConfig{CdUID: uid})
		require.Equal(t, []string{"provisioning failed: stage=api code=API_REJECTED (exit 31) http_status=404"}, exits)
		require.NotContains(t, exits[0], uid)
		// Support reads ctrld.log, and the app may not log the line.
		logText, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
		require.NoError(t, err)
		require.Contains(t, string(logText), exits[0])
	case "no-host-tools":
		// The whole run, with the startup metadata, must start no system
		// tool in an iOS app.
		marker := fakeHostTools(t)
		mobile.IsIOS = func() bool { return true }
		processCDFlagsFn = func(ctx context.Context, _ *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			startupMetadata(ctx)
			return nil, errors.New("preflight rejected")
		}
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		require.Equal(t, []string{"provisioning failed: stage=api code=API_UNREACHABLE (exit 30)"}, exits)
		requireNoHostTools(t, marker)
	case "token-exchange-redacts":
		// On iOS the UID exists only after the token exchange, so the
		// exchange must hand the UID to the log redaction for the whole run.
		const uid = "1e0rkx9a7tq"
		const token = "org-v1-provisiontoken"
		fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
			return &controld.ResolverConfig{UID: uid}, nil
		}
		processCDFlagsFn = func(context.Context, *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			mainLog.Load().Error().Msgf("resolver %s rejected for %s", cdUID, cdOrg)
			return nil, errors.New("preflight rejected")
		}
		runOnce(AppConfig{ProvisionID: token})
		require.Equal(t, 1, fetches)
		logText, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
		require.NoError(t, err)
		require.Contains(t, string(logText), "rejected for")
		require.NotContains(t, string(logText), uid)
		require.NotContains(t, string(logText), token)
	case "console-level":
		// Each start sets the console level from its own configuration, not
		// from the start before it. At -1 stdout must not get query names.
		runOnce(AppConfig{ProvisionID: "not a token", Verbose: 2})
		wantExit(provisionCodeProvisionTokenMalformed)
		require.Equal(t, zapcore.DebugLevel, consoleWriterLevel)
		runOnce(AppConfig{ProvisionID: "not a token", Verbose: -1})
		wantExit(provisionCodeProvisionTokenMalformed)
		require.Equal(t, ctrld.NoticeLevel, consoleWriterLevel)
	case "start-nameservers-logged":
		// The start applies the nameservers of the app before the log files
		// open. A dropped value must still reach the file that the app
		// exports.
		runOnce(AppConfig{CdUID: "testuid", Nameservers: "192.168.1.1:53,10.0.0.1"})
		logText, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
		require.NoError(t, err)
		require.Contains(t, string(logText), "192.168.1.1:53")
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

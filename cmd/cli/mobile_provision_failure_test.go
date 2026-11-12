package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/mobile"
	"github.com/Control-D-Inc/ctrld/internal/router"
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
		for _, mode := range []string{"token-shape", "listener-bind", "network-down", "network-stop", "proto-then-valid", "stale", "api-error-secret", "no-host-tools", "token-exchange-redacts", "console-level", "cd-listener-bind", "service-reset", "one-time-field", "no-config-file", "file-carry", "old-log-file", "bad-config-file", "bad-legacy-config-file", "cd-no-listener", "app-config-file", "missing-home-dir"} {
			t.Run(mode, func(t *testing.T) {
				if mode == "no-host-tools" && runtime.GOOS != "darwin" {
					t.Skip("the fake tools are the tools of macOS and iOS")
				}
				if configSearchModes[mode] && runtime.GOOS == "windows" {
					t.Skip("on Windows, ctrld looks for the config file next to its binary, not in HomeDir")
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
	newRouter = func(*ctrld.Config, bool) router.Router { return &startupTestRouter{} }
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
		if c.HomeDir == "" {
			c.HomeDir = dir
		}
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
	// On mobile an API failure names the api stage.
	const apiExitLine = "provisioning failed: stage=api code=API_UNREACHABLE (exit 30)"
	wantAPIExit := func() {
		t.Helper()
		require.Equal(t, []string{apiExitLine}, exits)
		exits = nil
	}
	// fetchCustomConfig is a processCDFlagsFn that answers with a custom
	// config and then fails. Like processCDFlags, it puts that config into
	// a new viper, which names no file. It records the config file that the
	// start read, and the file that a write of the answer goes to.
	var readFile, writeTarget string
	fetchCustomConfig := func(context.Context, *ctrld.Config) (*controld.ResolverConfig, error) {
		fetches++
		readFile = v.ConfigFileUsed()
		require.NoError(t, readBase64Config(base64.StdEncoding.EncodeToString([]byte("[listener.0]\n"))))
		writeTarget = configFileForWrite()
		return nil, errors.New("preflight rejected")
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
		wantAPIExit()
	case "stale":
		// A failure recorded outside any run must not abort the next one.
		pendingProvisionFailure.Store(newProvisionResult(provisionCodeUnclassified, "stale", nil))
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantAPIExit()
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
	case "no-host-tools":
		// The whole run, with the real router and the startup metadata,
		// must start no system tool in an iOS app. The router package reads
		// the platform at init, before this stub, so its own test covers it.
		marker := fakeHostTools(t)
		mobile.IsIOS = func() bool { return true }
		newRouter = router.New
		processCDFlagsFn = func(ctx context.Context, _ *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			startupMetadata(ctx)
			return nil, errors.New("preflight rejected")
		}
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantAPIExit()
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
		// from the start before it. The config file line comes before the
		// log files open, so only the console level of the start decides if
		// stdout gets it.
		const configLine = "loading config file from"
		out := consoleOutput(t, func() { runOnce(AppConfig{ProvisionID: "not a token", Verbose: 2}) })
		wantExit(provisionCodeProvisionTokenMalformed)
		require.Contains(t, out, configLine)
		out = consoleOutput(t, func() { runOnce(AppConfig{ProvisionID: "not a token", Verbose: -1}) })
		wantExit(provisionCodeProvisionTokenMalformed)
		require.NotContains(t, out, configLine)
	case "service-reset":
		// Each start takes its [service] values from its own AppConfig and
		// configuration file. A log path of the start before it must not
		// keep the next start at debug level.
		runOnce(AppConfig{CdUID: "testuid", Verbose: -1})
		require.Equal(t, filepath.Join(dir, "ctrld.log"), cfg.Service.LogPath)
		exits = nil
		RunMobile(&AppConfig{CdUID: "testuid", HomeDir: dir, UpstreamProto: "doh", Verbose: -1}, &callback, make(chan struct{}))
		require.Empty(t, cfg.Service.LogPath)
		require.Empty(t, cfg.Service.LogLevel)
		require.Equal(t, zerolog.NoticeLevel, zerolog.GlobalLevel())
	case "one-time-field":
		// Each start builds its logger again, so a line has one time field
		// after any number of starts.
		for range 3 {
			runOnce(AppConfig{CdUID: "testuid"})
		}
		logText, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
		require.NoError(t, err)
		line := lastLineContaining(t, string(logText), "starting ctrld")
		require.Equal(t, 1, strings.Count(line, `"time":`), line)
	case "file-carry":
		// Start 1 writes the configuration file before it fails. Its
		// AppConfig log values must not reach that file, or the next start
		// reads them back as its own configuration.
		const badUpstream = "[upstream.0]\ntype = \"bogus\"\nendpoint = \"https://example.invalid/x\"\n"
		require.NoError(t, os.WriteFile(configPath, []byte("[service]\n[listener.0]\nport = "+strconv.Itoa(freeUDPPort(t))+"\n[network.0]\ncidrs = [\"0.0.0.0/0\"]\n"+badUpstream), 0600))
		runOnce(AppConfig{Verbose: -1})
		require.Equal(t, filepath.Join(dir, "ctrld.log"), cfg.Service.LogPath)
		written, err := os.ReadFile(configPath)
		require.NoError(t, err)
		require.Contains(t, string(written), "[listener", "start 1 must write the file")
		require.NotContains(t, string(written), "log_path")
		require.NotContains(t, string(written), "log_level")
		exits = nil
		RunMobile(&AppConfig{HomeDir: dir, Verbose: -1}, &callback, make(chan struct{}))
		require.Empty(t, cfg.Service.LogPath)
		require.Empty(t, cfg.Service.LogLevel)
		require.Equal(t, zerolog.NoticeLevel, zerolog.GlobalLevel())
	case "old-log-file":
		// A start with no log path must not write to the log file of the
		// start before it, or list that file in its log header.
		appLog := filepath.Join(dir, "app.log")
		RunMobile(&AppConfig{CdUID: "testuid", HomeDir: dir, UpstreamProto: "doh", Verbose: -1, LogPath: appLog}, &callback, make(chan struct{}))
		before, err := os.ReadFile(appLog)
		require.NoError(t, err)
		RunMobile(&AppConfig{CdUID: "testuid", HomeDir: dir, UpstreamProto: "doh", Verbose: -1, Nameservers: "not-an-ip"}, &callback, make(chan struct{}))
		after, err := os.ReadFile(appLog)
		require.NoError(t, err)
		require.Equal(t, string(before), string(after))
		internalLog, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
		require.NoError(t, err)
		require.NotContains(t, string(internalLog), appLog)
	case "no-config-file":
		// A fresh install of an app that makes no config file. The mobile
		// viper has no defaults, and the working directory of an app is not
		// writable. So the start must write the default config, with a
		// listener, into HomeDir, and go on to the API.
		interceptMode = "off"
		configPath = ""
		homeConfig := filepath.Join(dir, "ctrld.toml")
		workDir := readOnlyWorkDir(t)
		useFreeMobileListenerPort(t)
		exchanges := 0
		fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
			exchanges++
			return &controld.ResolverConfig{UID: "testuid"}, nil
		}
		processCDFlagsFn = fetchCustomConfig
		requireFreshInstallFile := func() {
			t.Helper()
			written, err := os.ReadFile(homeConfig)
			require.NoError(t, err)
			require.Contains(t, string(written), "[listener.0]")
			entries, err := os.ReadDir(workDir)
			require.NoError(t, err)
			require.Empty(t, entries)
		}

		// The token start goes first, because a Control D start leaves its
		// UID for the next start. Before it knows the UID, its default write
		// probes port 53 for the listener, and no seam moves that port. A
		// host that holds port 53, or keeps it for root, stops the start
		// there, before the API.
		require.NoError(t, os.Remove(homeConfig))
		runOnce(AppConfig{ProvisionID: "org-v1-provisiontoken"})
		require.Len(t, exits, 1)
		if exits[0] == apiExitLine {
			exits = nil
			require.Equal(t, 1, exchanges)
			require.Equal(t, 1, fetches)
			require.Equal(t, homeConfig, writeTarget, "the config from the API must go to the same file")
		} else {
			wantExit(provisionCodeListenerBindFailed)
			require.Zero(t, exchanges)
		}
		requireFreshInstallFile()

		// The fixed address of a Control D start is on a free port here, so
		// this start reaches the API on any host.
		require.NoError(t, os.Remove(homeConfig))
		fetches, writeTarget = 0, ""
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantAPIExit()
		require.Equal(t, homeConfig, writeTarget, "the config from the API must go to the same file")
		requireFreshInstallFile()

		// The next start reads that file.
		fetches = 0
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantAPIExit()
		require.Equal(t, homeConfig, readFile)
		require.Equal(t, homeConfig, writeTarget)
		requireFreshInstallFile()
	case "app-config-file":
		// The consumer app makes an empty config.toml in HomeDir before each
		// start. The start reads it, writes to it, and makes no ctrld.toml.
		interceptMode = "off"
		configPath = ""
		require.NoError(t, os.Remove(filepath.Join(dir, "ctrld.toml")))
		appConfigFile := filepath.Join(dir, "config.toml")
		require.NoError(t, os.WriteFile(appConfigFile, nil, 0600))
		workDir := readOnlyWorkDir(t)
		processCDFlagsFn = fetchCustomConfig
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantAPIExit()
		require.Equal(t, appConfigFile, readFile)
		require.Equal(t, appConfigFile, writeTarget)
		require.NoFileExists(t, filepath.Join(dir, "ctrld.toml"))
		entries, err := os.ReadDir(workDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	case "missing-home-dir":
		// The app can pass a HomeDir that it could not make. The start then
		// cannot write the default config there. It must fail with a code
		// before the API, and the app must keep running.
		interceptMode = "off"
		configPath = ""
		missing := filepath.Join(dir, "missing")
		workDir := readOnlyWorkDir(t)
		useFreeMobileListenerPort(t)
		exchanges := 0
		fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
			exchanges++
			return nil, errors.New("exchange rejected")
		}
		// The token start goes first, because a Control D start leaves its
		// UID for the next start. Its probe of port 53 can fail first on a
		// host that holds that port. The failed write is recorded last, so
		// the start gets UNCLASSIFIED either way.
		for _, c := range []AppConfig{{ProvisionID: "org-v1-provisiontoken"}, {CdUID: "testuid"}} {
			c.HomeDir = missing
			runOnce(c)
			wantExit(provisionCodeUnclassified)
		}
		require.Zero(t, exchanges)
		require.Zero(t, fetches)
		require.NoDirExists(t, missing)
		entries, err := os.ReadDir(workDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	case "cd-listener-bind":
		// In Control D mode the address is fixed. When another process
		// holds it, the app gets the listener code, and ctrld does not move
		// to another address.
		interceptMode = "off"
		addr := net.JoinHostPort(mobileListenerIp(), strconv.Itoa(mobileListenerPort()))
		// If the test cannot bind the address, ctrld cannot either.
		if udp, err := net.ListenPacket("udp", addr); err == nil {
			defer udp.Close()
		}
		if tcp, err := net.Listen("tcp", addr); err == nil {
			defer tcp.Close()
		}
		processCDFlagsFn = func(_ context.Context, c *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			*c = ctrld.Config{
				Upstream: map[string]*ctrld.UpstreamConfig{"0": {Endpoint: "https://dns.controld.com/testuid", Type: "doh", Timeout: 5000}},
				Listener: map[string]*ctrld.ListenerConfig{"0": {}},
			}
			setNetworkDefaultValue(c)
			return &controld.ResolverConfig{}, nil
		}
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantExit(provisionCodeListenerAddrUnavail)
		require.Equal(t, addr, net.JoinHostPort(cfg.Listener["0"].IP, strconv.Itoa(cfg.Listener["0"].Port)))
	case "bad-config-file":
		// The app can end during a write of the config file. A file that is
		// not TOML must fail the start, and the app must keep running.
		configPath = ""
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ctrld.toml"), []byte("[listener.0"), 0600))
		// The start must stop before the wait for the network. A failure
		// there replaces the config error.
		networkWaits := 0
		networkUp = func(<-chan struct{}) bool { networkWaits++; return true }
		runOnce(AppConfig{CdUID: "testuid"})
		wantExit(provisionCodeUnclassified)
		require.Zero(t, networkWaits)
		require.Zero(t, fetches)
		r, err := readProvisionResultAt(filepath.Join(dir, provisionResultFileName))
		require.NoError(t, err)
		require.Contains(t, r.Message, "failed to decode config file at line: 1")
	case "bad-legacy-config-file":
		// ctrld reads config.toml before ctrld.toml. A bad config.toml must
		// fail the start, and must not lead to a default ctrld.toml. The
		// working directory of an app is not writable.
		interceptMode = "off"
		configPath = ""
		require.NoError(t, os.Remove(filepath.Join(dir, "ctrld.toml")))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[listener.0"), 0600))
		workDir := readOnlyWorkDir(t)
		// The token start goes first, because a Control D start leaves its
		// UID for the next start.
		for _, c := range []AppConfig{{ProvisionID: "org-v1-provisiontoken"}, {CdUID: "testuid"}} {
			runOnce(c)
			wantExit(provisionCodeUnclassified)
			r, err := readProvisionResultAt(filepath.Join(dir, provisionResultFileName))
			require.NoError(t, err)
			require.Contains(t, r.Message, "failed to decode config file at line: 1")
		}
		require.Zero(t, fetches)
		for _, d := range []string{dir, workDir} {
			require.NoFileExists(t, filepath.Join(d, "ctrld.toml"))
		}
	case "cd-no-listener":
		interceptMode = "off"
		require.NoError(t, os.Remove(configPath))
		processCDFlagsFn = func(_ context.Context, c *ctrld.Config) (*controld.ResolverConfig, error) {
			fetches++
			*c = ctrld.Config{
				Upstream: map[string]*ctrld.UpstreamConfig{"0": {Endpoint: "https://dns.controld.com/testuid", Type: "doh", Timeout: 5000}},
			}
			setNetworkDefaultValue(c)
			return &controld.ResolverConfig{}, nil
		}
		runOnce(AppConfig{CdUID: "testuid"})
		require.Equal(t, 1, fetches)
		wantExit(provisionCodeUnclassified)
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

// configSearchModes are the modes that need ctrld to look for the config
// file in HomeDir.
var configSearchModes = map[string]bool{"bad-config-file": true, "bad-legacy-config-file": true, "no-config-file": true, "app-config-file": true, "missing-home-dir": true}

// useFreeMobileListenerPort moves the fixed listener address of a Control D
// start on mobile to a free port, because a host can hold port 53.
func useFreeMobileListenerPort(t *testing.T) {
	port := freeLocalPort(t)
	old := mobileListenerPort
	t.Cleanup(func() { mobileListenerPort = old })
	mobileListenerPort = func() int { return port }
}

// readOnlyWorkDir makes the working directory a new directory that the test
// cannot write, as on a device.
func readOnlyWorkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0500))
	t.Chdir(dir)
	return dir
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func lastLineContaining(t *testing.T, text, substr string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], substr) {
			return lines[i]
		}
	}
	t.Fatalf("no line contains %q in:\n%s", substr, text)
	return ""
}

// consoleOutput returns what start writes to stdout. The console writer takes
// os.Stdout when a start builds it, so a file in its place gets the lines.
func consoleOutput(t *testing.T, start func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	defer f.Close()
	oldStdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = oldStdout }()
	start()
	out, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return string(out)
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

	p.reportServeDNSFailure("0", errors.New("serve failed"))

	require.Equal(t, []string{newProvisionResult(provisionCodeUnclassified, "", nil).failureLine()}, exits)
	require.Nil(t, pendingProvisionFailure.Load())
}

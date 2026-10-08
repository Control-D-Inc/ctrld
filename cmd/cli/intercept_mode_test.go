package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// useInterceptByDefault pins whether this host intercepts when no mode is
// selected, so the default is tested the same way on every CI host. It also
// pins the process to a foreground run; useRunningAsService changes that.
func useInterceptByDefault(t *testing.T, supported bool) {
	t.Helper()
	old, oldService := interceptByDefault, runningAsService
	interceptByDefault = supported
	runningAsService = func() bool { return false }
	t.Cleanup(func() { interceptByDefault, runningAsService = old, oldService })
}

// useRunningAsService pins whether this process runs as the installed service.
// Call it after useInterceptByDefault.
func useRunningAsService(t *testing.T, asService bool) {
	t.Helper()
	old := runningAsService
	runningAsService = func() bool { return asService }
	t.Cleanup(func() { runningAsService = old })
}

// useInterceptBlockedByOSUpstream pins whether an OS-resolver upstream rules
// out intercept mode, as it does on macOS.
func useInterceptBlockedByOSUpstream(t *testing.T, blocked bool) {
	t.Helper()
	old := interceptBlockedByOSUpstream
	interceptBlockedByOSUpstream = blocked
	t.Cleanup(func() { interceptBlockedByOSUpstream = old })
}

// useInterceptModeState restores the package intercept state a test changes.
func useInterceptModeState(t *testing.T) {
	t.Helper()
	mode, source, intercept, hard := interceptMode, interceptModeSource, dnsIntercept, hardIntercept
	t.Cleanup(func() {
		interceptMode, interceptModeSource, dnsIntercept, hardIntercept = mode, source, intercept, hard
	})
}

// The full precedence table (issue #589): --intercept-mode, then
// service.intercept_mode, then the platform default. "off" at either explicit
// level is final, even over a persisted "dns".
func TestResolveInterceptModePrecedence(t *testing.T) {
	for _, tc := range []struct {
		flag, config string
		supported    bool
		want, source string
	}{
		// Supported desktop platforms (macOS, Windows workstation).
		{flag: "", config: "", supported: true, want: "dns", source: interceptModeSourceDefault},
		{flag: "", config: "dns", supported: true, want: "dns", source: interceptModeSourceConfig},
		{flag: "", config: "hard", supported: true, want: "hard", source: interceptModeSourceConfig},
		{flag: "", config: "off", supported: true, want: "off", source: interceptModeSourceConfig},
		{flag: "dns", config: "", supported: true, want: "dns", source: interceptModeSourceFlag},
		{flag: "hard", config: "dns", supported: true, want: "hard", source: interceptModeSourceFlag},
		{flag: "off", config: "", supported: true, want: "off", source: interceptModeSourceFlag},
		{flag: "off", config: "dns", supported: true, want: "off", source: interceptModeSourceFlag},
		{flag: "off", config: "hard", supported: true, want: "off", source: interceptModeSourceFlag},
		{flag: "dns", config: "off", supported: true, want: "dns", source: interceptModeSourceFlag},
		// Windows Server and unsupported platforms keep interface DNS mode
		// by default; explicit selections still mean what they say, and
		// intercept works on Windows Server when selected.
		{flag: "", config: "", supported: false, want: "", source: interceptModeSourceDefault},
		{flag: "", config: "dns", supported: false, want: "dns", source: interceptModeSourceConfig},
		{flag: "off", config: "dns", supported: false, want: "off", source: interceptModeSourceFlag},
		{flag: "hard", config: "", supported: false, want: "hard", source: interceptModeSourceFlag},
	} {
		useInterceptByDefault(t, tc.supported)
		cfg := &ctrld.Config{}
		cfg.Service.InterceptMode = tc.config
		mode, source := resolveInterceptMode(tc.flag, cfg)
		if mode != tc.want || source != tc.source {
			t.Errorf("flag=%q config=%q supported=%v: got (%q, %q), want (%q, %q)",
				tc.flag, tc.config, tc.supported, mode, source, tc.want, tc.source)
		}
	}
}

// iOS builds the darwin files and counts as a desktop platform there, but it
// has no pf: it must never intercept by default.
func TestInterceptByDefaultOn(t *testing.T) {
	for _, tc := range []struct {
		goos    string
		desktop bool
		want    bool
	}{
		{goos: "darwin", desktop: true, want: true},
		{goos: "windows", desktop: true, want: true},
		{goos: "windows", desktop: false, want: false}, // Windows Server
		{goos: "ios", desktop: true, want: false},
		{goos: "android", desktop: false, want: false},
		{goos: "linux", desktop: false, want: false},
	} {
		if got := interceptByDefaultOn(tc.goos, tc.desktop); got != tc.want {
			t.Errorf("interceptByDefaultOn(%q, %v) = %v, want %v", tc.goos, tc.desktop, got, tc.want)
		}
	}
}

// On macOS an OS-resolver upstream cannot run in intercept mode, because pf
// redirects ctrld's own port-53 queries to it back to ctrld. The default then
// keeps interface DNS mode, where such a config works; an explicit selection
// still selects intercept mode and fails on it, as before.
func TestDefaultInterceptModeStepsBackForOSUpstream(t *testing.T) {
	useInterceptByDefault(t, true)
	withUpstream := func(typ string) *ctrld.Config {
		return &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: typ}}}
	}
	for _, tc := range []struct {
		name        string
		blockedByOS bool
		cfg         *ctrld.Config
		flag        string
		want        string
		wantBlocked bool
	}{
		{name: "doh upstream on macOS", blockedByOS: true, cfg: withUpstream(ctrld.ResolverTypeDOH), want: "dns"},
		{name: "os upstream on macOS", blockedByOS: true, cfg: withUpstream(ctrld.ResolverTypeOS), want: "", wantBlocked: true},
		{name: "untyped upstream on macOS", blockedByOS: true, cfg: withUpstream(""), want: "", wantBlocked: true},
		{name: "os upstream on Windows", blockedByOS: false, cfg: withUpstream(ctrld.ResolverTypeOS), want: "dns"},
		{name: "explicit dns with os upstream on macOS", blockedByOS: true, cfg: withUpstream(ctrld.ResolverTypeOS), flag: "dns", want: "dns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useInterceptBlockedByOSUpstream(t, tc.blockedByOS)
			if mode, _ := resolveInterceptMode(tc.flag, tc.cfg); mode != tc.want {
				t.Fatalf("resolveInterceptMode = %q, want %q", mode, tc.want)
			}
			if tc.flag == "" {
				if _, blocked := defaultInterceptMode(tc.cfg); (blocked != nil) != tc.wantBlocked {
					t.Fatalf("default blocked = %v, want blocked = %v", blocked, tc.wantBlocked)
				}
			}
		})
	}
}

// The listener binding strategy follows the same precedence, so a macOS start
// that intercepts by default also binds the way intercept mode needs.
func TestListenerInterceptModeUsesPlatformDefault(t *testing.T) {
	useInterceptModeState(t)
	interceptMode = ""
	cfg := &ctrld.Config{}

	useInterceptByDefault(t, true)
	if got := listenerInterceptMode(cfg); got != "dns" {
		t.Errorf("supported, unset: listenerInterceptMode = %q, want dns", got)
	}
	cfg.Service.InterceptMode = "off"
	if got := listenerInterceptMode(cfg); got != "off" {
		t.Errorf("supported, config off: listenerInterceptMode = %q, want off", got)
	}
	cfg.Service.InterceptMode = ""
	useInterceptByDefault(t, false)
	if got := listenerInterceptMode(cfg); got != "" {
		t.Errorf("unsupported, unset: listenerInterceptMode = %q, want empty", got)
	}
}

// setDNS starts intercept mode by default on the supported desktop platforms,
// and never by default anywhere else: on Windows Server an unset mode keeps
// interface DNS mode, and on an unsupported platform it must not even try, so
// nothing logs an intercept-start failure.
func TestSetDNSInterceptDefault(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flag, config  string
		supported     bool
		wantIntercept bool
		wantSource    string
	}{
		{name: "supported, unset", supported: true, wantIntercept: true, wantSource: interceptModeSourceDefault},
		{name: "supported, explicit off", flag: "off", supported: true, wantSource: interceptModeSourceFlag},
		{name: "supported, explicit off over persisted dns", flag: "off", config: "dns", supported: true, wantSource: interceptModeSourceFlag},
		{name: "supported, persisted off", config: "off", supported: true, wantSource: interceptModeSourceConfig},
		{name: "supported, persisted hard", config: "hard", supported: true, wantIntercept: true, wantSource: interceptModeSourceConfig},
		{name: "not a desktop platform, unset", supported: false, wantSource: interceptModeSourceDefault},
		{name: "not a desktop platform, explicit dns", flag: "dns", supported: false, wantIntercept: true, wantSource: interceptModeSourceFlag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useInterceptModeState(t)
			useInterceptByDefault(t, tc.supported)
			h := newInterceptFallbackHarness(t, &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 5354})
			cfg.Service.InterceptMode = tc.config
			interceptMode, interceptModeSource, dnsIntercept, hardIntercept = tc.flag, "", false, false

			h.run(t)

			if got := h.interceptCalls > 0; got != tc.wantIntercept {
				t.Fatalf("intercept start attempted = %v, want %v", got, tc.wantIntercept)
			}
			if interceptModeSource != tc.wantSource {
				t.Fatalf("interceptModeSource = %q, want %q", interceptModeSource, tc.wantSource)
			}
		})
	}
}

func TestInterceptModeFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		want   string
		wantOK bool
	}{
		{args: nil},
		{args: []string{"/usr/local/bin/ctrld", "run", "--cd=abc"}},
		{args: []string{"/usr/local/bin/ctrld", "run", "--intercept-mode", "dns", "--cd=abc"}, want: "dns", wantOK: true},
		{args: []string{"ctrld.exe", "run", "--intercept-mode=hard"}, want: "hard", wantOK: true},
		{args: []string{"ctrld", "run", "--intercept-mode", "off"}, want: "off", wantOK: true},
		{args: []string{"ctrld", "run", "--intercept-mode"}, want: "", wantOK: true},
	} {
		got, ok := interceptModeFromArgs(tc.args)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("interceptModeFromArgs(%q) = (%q, %v), want (%q, %v)", tc.args, got, ok, tc.want, tc.wantOK)
		}
	}
}

// useInterceptModeDefault pins the hidden --intercept-mode-default flag.
func useInterceptModeDefault(t *testing.T, on bool) {
	t.Helper()
	old := interceptModeDefault
	interceptModeDefault = on
	t.Cleanup(func() { interceptModeDefault = old })
}

func TestInterceptDefaultFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{args: nil},
		{args: []string{"ctrld", "run", "--cd=abc"}},
		{args: []string{"ctrld", "run", "--intercept-mode-default=true"}, want: true},
		{args: []string{"ctrld", "run", "--intercept-mode-default"}, want: true},
		{args: []string{"ctrld", "run", "--intercept-mode-default=false"}},
		{args: []string{"ctrld", "run", "--intercept-mode=dns"}},
	} {
		if got := interceptDefaultFromArgs(tc.args); got != tc.want {
			t.Errorf("interceptDefaultFromArgs(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
	// The marker must not read as --intercept-mode, and the reverse.
	if _, ok := interceptModeFromArgs([]string{"ctrld", "run", "--intercept-mode-default=true"}); ok {
		t.Error("the marker read as --intercept-mode")
	}
}

// "ctrld start" records what a service it installs gets when no mode is
// selected. A fresh install gets the --intercept-mode-default marker, so the
// service applies the default itself, below service.intercept_mode. A
// reinstall keeps the existing service's mode or marker, and an existing
// service that records neither was a Standard install, so it is pinned to
// "off" (#589).
func TestInstallInterceptMode(t *testing.T) {
	legacyArgs := []string{"/usr/local/bin/ctrld", "run", "--cd=abc", "--config=/etc/controld/ctrld.toml"}
	with := func(extra ...string) []string { return append(append([]string{}, legacyArgs...), extra...) }
	withConfigMode := func(mode string) *ctrld.Config {
		cfg := &ctrld.Config{}
		cfg.Service.InterceptMode = mode
		return cfg
	}
	for _, tc := range []struct {
		name         string
		desktop      bool
		flag         string
		cfg          *ctrld.Config
		installed    bool
		existingArgs []string
		wantMode     string
		wantMarker   bool
	}{
		{name: "fresh install is marked for the default", desktop: true, cfg: &ctrld.Config{}, wantMarker: true},
		{name: "fresh install with a config mode is still marked", desktop: true, cfg: withConfigMode("hard"), wantMarker: true},
		{name: "explicit flag records nothing more", desktop: true, flag: "off", cfg: &ctrld.Config{}},
		{name: "fresh install on Windows Server", desktop: false, cfg: &ctrld.Config{}},
		{name: "existing Standard service is pinned off", desktop: true, cfg: &ctrld.Config{}, installed: true, existingArgs: legacyArgs, wantMode: "off"},
		{name: "unreadable existing service is pinned off", desktop: true, cfg: &ctrld.Config{}, installed: true, existingArgs: nil, wantMode: "off"},
		{name: "existing service with a config mode is left to the config", desktop: true, cfg: withConfigMode("dns"), installed: true, existingArgs: legacyArgs},
		{name: "existing default service keeps the marker", desktop: true, cfg: &ctrld.Config{}, installed: true,
			existingArgs: with("--intercept-mode-default=true"), wantMarker: true},
		{name: "existing dns service keeps dns", desktop: true, cfg: &ctrld.Config{}, installed: true,
			existingArgs: with("--intercept-mode", "dns"), wantMode: "dns"},
		{name: "existing hard service keeps hard", desktop: true, cfg: &ctrld.Config{}, installed: true,
			existingArgs: with("--intercept-mode=hard"), wantMode: "hard"},
		{name: "existing off service keeps off", desktop: true, cfg: &ctrld.Config{}, installed: true,
			existingArgs: with("--intercept-mode", "off"), wantMode: "off"},
		{name: "existing service on Windows Server records nothing", desktop: false, cfg: &ctrld.Config{}, installed: true, existingArgs: legacyArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useInterceptByDefault(t, tc.desktop)
			mode, marker := installInterceptMode(tc.flag, tc.cfg, tc.installed, tc.existingArgs)
			if mode != tc.wantMode || marker != tc.wantMarker {
				t.Fatalf("installInterceptMode = (%q, marker %v), want (%q, marker %v)", mode, marker, tc.wantMode, tc.wantMarker)
			}
		})
	}
}

// How an installed service resolves its mode when its arguments select none.
//
//   - The legacy upgrade case (#589): a Standard service installed before the
//     dns default has neither a mode nor the marker. Whatever upgrades its
//     binary, ctrld upgrade from an older release included, the new binary
//     runs it with the same arguments, and it must stay in interface DNS mode.
//   - A service "ctrld start" marked as a fresh install applies the default,
//     but below service.intercept_mode: a mode from a Control D custom config
//     or a --base64_config wins.
//   - The default is decided against the config the service runs with, so an
//     os upstream there steps it back, with that reason, not the legacy one.
//   - A foreground run uses the default.
func TestInstalledServiceInterceptModeResolution(t *testing.T) {
	osUpstream := map[string]*ctrld.UpstreamConfig{"0": {Type: ctrld.ResolverTypeOS}}
	for _, tc := range []struct {
		name          string
		asService     bool
		marker        bool
		configMode    string
		upstreams     map[string]*ctrld.UpstreamConfig
		wantMode      string
		wantIntercept bool
		wantReason    error // checked when the default is not applied
	}{
		{name: "upgraded legacy Standard service", asService: true, wantMode: "", wantReason: errInterceptDefaultLegacyService},
		{name: "fresh default service", asService: true, marker: true, wantMode: "dns", wantIntercept: true},
		{name: "fresh default service, config selects hard", asService: true, marker: true, configMode: "hard", wantMode: "hard", wantIntercept: true},
		{name: "fresh default service, config selects off", asService: true, marker: true, configMode: "off", wantMode: "off"},
		{name: "fresh default service, os upstream", asService: true, marker: true, upstreams: osUpstream, wantMode: ""},
		{name: "foreground run", asService: false, wantMode: "dns", wantIntercept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useInterceptModeState(t)
			useInterceptByDefault(t, true)
			useInterceptBlockedByOSUpstream(t, true)
			useRunningAsService(t, tc.asService)
			useInterceptModeDefault(t, tc.marker)
			h := newInterceptFallbackHarness(t, &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 5354})
			cfg.Service.InterceptMode = tc.configMode
			cfg.Upstream = tc.upstreams
			interceptMode, interceptModeSource, dnsIntercept, hardIntercept = "", "", false, false

			if got := listenerInterceptMode(&cfg); got != tc.wantMode {
				t.Fatalf("listenerInterceptMode = %q, want %q", got, tc.wantMode)
			}
			h.run(t)
			if got := h.interceptCalls > 0; got != tc.wantIntercept {
				t.Fatalf("intercept start attempted = %v, want %v", got, tc.wantIntercept)
			}
			if tc.configMode == "" && tc.wantMode == "" {
				_, reason := defaultInterceptMode(&cfg)
				if tc.wantReason != nil && reason != tc.wantReason {
					t.Fatalf("default reason = %v, want %v", reason, tc.wantReason)
				}
				if tc.wantReason == nil && (reason == nil || reason == errInterceptDefaultLegacyService) {
					t.Fatalf("default reason = %v, want the os upstream reason", reason)
				}
			}
		})
	}
}

// The marker is a hidden flag of "ctrld run", recorded as one argument.
func TestRunCmdInterceptModeDefaultFlag(t *testing.T) {
	useInterceptModeDefault(t, false)
	cmd := initRunCmd()
	t.Cleanup(func() { rootCmd.RemoveCommand(cmd) })
	f := cmd.Flags().Lookup("intercept-mode-default")
	if f == nil || !f.Hidden {
		t.Fatalf("--intercept-mode-default flag = %+v, want a hidden flag", f)
	}
	if err := cmd.ParseFlags([]string{"--intercept-mode-default=true"}); err != nil {
		t.Fatal(err)
	}
	if !interceptModeDefault {
		t.Fatal("--intercept-mode-default=true did not set the marker")
	}
}

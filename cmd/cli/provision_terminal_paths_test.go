package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestFailProvisionUnclassified pins the fallback every terminal path on the
// provisioning boundary uses when it predates a stable code: it persists
// UNCLASSIFIED, calls notify, and exits at the code's exit number.
func TestFailProvisionUnclassified(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	notified := false

	failProvisionUnclassified("something failed with no dedicated code", func() { notified = true })

	if !notified {
		t.Error("notify not called")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeUnclassified] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeUnclassified])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeUnclassified) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeUnclassified)
	}
	if r.Stage != string(provisionStageService) {
		t.Errorf("stage = %q, want %q", r.Stage, provisionStageService)
	}
	if !strings.Contains(r.Message, "something failed") {
		t.Errorf("message = %q, want it to contain the given message", r.Message)
	}
}

// TestNotifyExitToLogServer pins the method every run()-side failure uses to
// unblock a waiting "ctrld start": it closes the log connection exactly when
// one is set, and is a no-op otherwise.
func TestNotifyExitToLogServer(t *testing.T) {
	t.Run("nil connection is a no-op", func(t *testing.T) {
		p := &prog{}
		p.notifyExitToLogServer() // must not panic
	})

	t.Run("closes a set connection", func(t *testing.T) {
		p := &prog{}
		fc := &fakeCloser{}
		p.logConn = fc
		p.notifyExitToLogServer()
		if !fc.closed {
			t.Error("expected logConn to be closed")
		}
	})
}

type fakeCloser struct{ closed bool }

func (f *fakeCloser) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeCloser) Close() error                { f.closed = true; return nil }

// TestValidateFirewallModeFlag covers the shared validator behind both
// --firewall-mode call sites (the early "ctrld start" check and run()'s own
// check on the daemon side). Neither has a dedicated code, so both fall back
// to UNCLASSIFIED.
func TestValidateFirewallModeFlag(t *testing.T) {
	t.Run("flag not changed proceeds regardless of value", func(t *testing.T) {
		exitCode, _ := stubProvisionGlobals(t)
		if !validateFirewallModeFlag(false, "garbage", nil) {
			t.Error("validateFirewallModeFlag() = false, want true when the flag was not set")
		}
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want no exit", *exitCode)
		}
	})

	t.Run("valid values proceed", func(t *testing.T) {
		exitCode, _ := stubProvisionGlobals(t)
		for _, mode := range []string{"off", "on"} {
			if !validateFirewallModeFlag(true, mode, nil) {
				t.Errorf("validateFirewallModeFlag(true, %q) = false, want true", mode)
			}
		}
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want no exit", *exitCode)
		}
	})

	t.Run("invalid value is classified UNCLASSIFIED and notifies", func(t *testing.T) {
		exitCode, _ := stubProvisionGlobals(t)
		notified := false
		if validateFirewallModeFlag(true, "bogus", func() { notified = true }) {
			t.Error("validateFirewallModeFlag(true, \"bogus\") = true, want false")
		}
		if !notified {
			t.Error("notify not called")
		}
		if *exitCode != provisionExitCodeForCode[provisionCodeUnclassified] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeUnclassified])
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatalf("no provision result written: %v", err)
		}
		if r.Code != string(provisionCodeUnclassified) {
			t.Errorf("code = %q, want %q", r.Code, provisionCodeUnclassified)
		}
		if !strings.Contains(r.Message, "off") || !strings.Contains(r.Message, "on") {
			t.Errorf("message = %q, want it to name the allowed values", r.Message)
		}
	})
}

// TestReportServeDNSFailure covers the one prog.go path where a listener
// bound successfully (LISTENER_* already ruled that out) but the proxy
// itself failed to start serving - a distinct failure with no dedicated
// code.
func TestReportServeDNSFailure(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	notified := false
	p.logConn = &fakeCloserNotify{fn: func() { notified = true }}

	p.reportServeDNSFailure("0", errors.New("bind lost mid-flight"))

	if !notified {
		t.Error("expected the log connection to be closed")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeUnclassified] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeUnclassified])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeUnclassified) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeUnclassified)
	}
	if !strings.Contains(r.Message, "listener.0") {
		t.Errorf("message = %q, want it to name the listener", r.Message)
	}
}

type fakeCloserNotify struct{ fn func() }

func (f *fakeCloserNotify) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeCloserNotify) Close() error                { f.fn(); return nil }

// TestRefuseFallbackFatalDefault covers the production refuseFallbackFatal
// closure (not the test-harness override other tests install): it classifies
// UNCLASSIFIED and notifies through the given prog's log connection.
func TestRefuseFallbackFatalDefault(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	notified := false
	p.logConn = &fakeCloserNotify{fn: func() { notified = true }}

	refuseFallbackFatal(p, "cannot fall back: %s", "port 53 is unavailable")

	if !notified {
		t.Error("expected the log connection to be closed")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeUnclassified] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeUnclassified])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeUnclassified) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeUnclassified)
	}
	if !strings.Contains(r.Message, "port 53 is unavailable") {
		t.Errorf("message = %q, want it to contain the formatted detail", r.Message)
	}
}

// terminalPathCase documents one terminal path this lane audited under
// "ctrld start --cd-org": where it lives, what triggers it, and the code it
// now reports. reachable names a test that exercises the real call site
// end-to-end (through the seams this package already exposes); a path deep
// inside Start()/run() with no seam to trigger it in isolation is documented
// here with reachable == "" and relies on the shared helper tests above
// (TestFailProvisionUnclassified, TestNotifyExitToLogServer,
// TestValidateFirewallModeFlag, TestReportServeDNSFailure,
// TestRefuseFallbackFatalDefault) to prove the wiring it calls into.
type terminalPathCase struct {
	file      string
	scenario  string
	code      provisionFailureCode
	reachable string // name of the test proving this exact site, or "" if only the shared helper is exercised
}

// TestProvisioningTerminalPathAudit is the committed enumeration required for
// "ctrld start --cd-org": every Fatal/os.Exit found by re-deriving the
// requirement (grepping commands_service_start.go, cli.go's run() and its
// callers cdUIDFromProvToken/handleAPIPreflightFailure, commands_run.go, and
// prog.go's pre-daemonization paths), reconciled against a code. None of them
// may reach a bare Fatal/os.Exit any more; each row's code is asserted
// against the known contract maps so a typo'd code name fails this test.
func TestProvisioningTerminalPathAudit(t *testing.T) {
	cases := []terminalPathCase{
		// commands_service_start.go (parent "ctrld start" process)
		{"commands_service_start.go", "--intercept-mode is not off/dns/hard", provisionCodeInterceptModeInvalid, "TestValidateInterceptModeFlag"},
		{"commands_service_start.go", "--firewall-mode is not off/on", provisionCodeUnclassified, "TestValidateFirewallModeFlag"},
		{"commands_service_start.go / cli.go RunCobraCommand", "explicit empty --cd-org", provisionCodeProvisionTokenMalformed, "TestCheckStrFlagEmptyClassifiesEmptyCdOrg"},
		{"commands_service_start.go", "--cd/--cd-org used together with --nextdns", provisionCodeInvalidFlagCombination, "TestValidateCdAndNextDNSFlagsClassifiesConflict"},
		{"commands_service_start.go", "initializeServiceManagerWithServiceConfig fails", provisionCodeUnclassified, "TestServiceCommandStartClassifiesServiceManagerInitFailure"},
		{"commands_service_start.go / cli.go run()", "--proto is not doh/doh3 once --cd is set", provisionCodeInvalidFlagCombination, "TestValidateCdUpstreamProtocol"},
		{"commands_service_start.go", "removeServiceFlag fails while upgrading an existing service's intercept mode", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "appendServiceFlag(\"--intercept-mode\") fails during the same upgrade", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "appendServiceFlag(mode) fails during the same upgrade", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "config unmarshal fails restarting an already-installed service", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "doTasksE fails on a non-service-stage task restarting an existing service", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "socketDir() fails restarting an existing service", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "config unmarshal fails on a fresh install", provisionCodeUnclassified, ""},
		{"commands_service_start.go", "doTasksE fails on a non-service-stage task on a fresh install", provisionCodeUnclassified, ""},

		// cli.go run() (the "ctrld run" child process --cd-org spawns, or a direct "ctrld run --cd-org" invocation)
		{"cli.go run()", "called with a nil stop channel", provisionCodeUnclassified, ""},
		{"cli.go run()", "--daemon on windows", provisionCodeUnclassified, ""},
		{"cli.go run()", "newService fails building the background service handle", provisionCodeUnclassified, ""},
		{"cli.go run()", "readBase64Config fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "config unmarshal fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "network is not up", provisionCodeUnclassified, ""},
		{"cli.go run()", "--firewall-mode is not off/on (daemon-side check)", provisionCodeUnclassified, "TestValidateFirewallModeFlag"},
		{"cli.go run()", "writeConfigFile fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "validateConfig fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "os.Executable fails in daemon respawn", provisionCodeUnclassified, ""},
		{"cli.go run()", "os.Getwd fails in daemon respawn", provisionCodeUnclassified, ""},
		{"cli.go run()", "cmd.Start fails in daemon respawn", provisionCodeUnclassified, ""},

		// prog.go (pre-daemonization: listener startup and DNS-intercept setup)
		{"prog.go (p *prog) run()", "serveDNS fails after the listener already bound", provisionCodeUnclassified, "TestReportServeDNSFailure"},
		{"prog.go (p *prog) setDNS()", "DNS intercept fails and the interface-DNS fallback cannot reach a non-53 listener", provisionCodeUnclassified, "TestRefuseFallbackFatalDefault"},
	}

	for _, tc := range cases {
		if _, ok := provisionStageForCode[tc.code]; !ok {
			t.Errorf("%s: %s: code %s is not a known contract code", tc.file, tc.scenario, tc.code)
		}
		if tc.reachable != "" {
			continue
		}
		t.Logf("documented (exercised only via shared helper wiring, not a standalone seam): %s: %s -> %s", tc.file, tc.scenario, tc.code)
	}

	// Out of scope, left as bare Fatal/os.Exit deliberately, with reasons:
	//
	//   - cli.go run(): stopCh nil check is still bare-Fatal-free (converted
	//     above) but is genuinely unreachable from any CLI invocation - the
	//     CLI always constructs a fresh channel. Converted anyway above for
	//     consistency, not because it is reachable.
	//   - prog.go (p *prog) setDNS() line ~995's own --intercept-mode check:
	//     explicitly left alone per T6 - it is the "runtime validation in
	//     prog.go" validInterceptMode's own doc comment calls out as distinct
	//     from "the early start command check" that got INTERCEPT_MODE_INVALID.
	//   - prog.go line ~912 (deactivation pin) and commands_service_start.go's
	//     own deactivation-pin os.Exit: explicitly out of scope per the lane
	//     contract ("pin-check 126 untouched").
	//   - service.go: checkHasElevatedPrivilege's os.Exit(1) in the "start"
	//     PreRun. It runs before RunE, in a process that cannot write to
	//     /etc/controld, so no result file is possible there. The postinstall
	//     always runs as root, and the message names the fix.
	//   - cli.go: general CLI/config-parsing helpers (readConfigFile,
	//     decoderErrorFromTomlFile, processNoConfigFlags, processListenFlag,
	//     tryReadingConfigWithNotice's userHomeDir failure): these predate and
	//     apply uniformly across every ctrld invocation mode (config-file
	//     mode, no-config mode, nextdns mode), not specifically to --cd-org
	//     provisioning. Out of scope for this lane's --cd-org enumeration.
	//   - checkStrFlagEmpty for --cd (cdUidFlagName) keeps its bare fatal:
	//     only the --cd-org case above is a provisioning-token value.
}

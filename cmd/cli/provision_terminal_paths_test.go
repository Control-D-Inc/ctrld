package cli

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
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
// unblock a waiting "ctrld start": it writes msgExit to the log connection
// exactly when one is set, and is a no-op otherwise.
func TestNotifyExitToLogServer(t *testing.T) {
	t.Run("nil connection is a no-op", func(t *testing.T) {
		p := &prog{}
		p.notifyExitToLogServer() // must not panic
	})

	t.Run("writes msgExit to a set connection", func(t *testing.T) {
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		p := &prog{logConn: client}

		received := make(chan string, 1)
		go func() {
			buf := make([]byte, 64)
			n, _ := server.Read(buf)
			received <- string(buf[:n])
		}()

		p.notifyExitToLogServer()

		select {
		case got := <-received:
			if got != msgExit {
				t.Errorf("wrote %q, want %q", got, msgExit)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for notifyExitToLogServer to write")
		}
	})
}

// TestReportServeDNSFailure covers the one prog.go path where a listener
// bound successfully (LISTENER_* already ruled that out) but the proxy
// itself failed to start serving - a distinct failure with no dedicated
// code.
func TestReportServeDNSFailure(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
	}()
	p := &prog{logConn: client}

	p.reportServeDNSFailure("0", errors.New("bind lost mid-flight"))

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

// TestRefuseFallbackFatalDefault covers the production refuseFallbackFatal
// closure (not the test-harness override other tests install): it
// classifies UNCLASSIFIED and notifies through the given prog's log
// connection.
func TestRefuseFallbackFatalDefault(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
	}()
	p := &prog{logConn: client}

	refuseFallbackFatal(p, "cannot fall back: %s", "port 53 is unavailable")

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
// inside the start command's Run closure / run() with no seam to trigger it
// in isolation is documented here with reachable == "" and relies on the
// shared helper tests above (TestFailProvisionUnclassified,
// TestNotifyExitToLogServer, TestReportServeDNSFailure,
// TestRefuseFallbackFatalDefault) to prove the wiring it calls into.
type terminalPathCase struct {
	file      string
	scenario  string
	code      provisionFailureCode
	reachable string // name of the test proving this exact site, or "" if only the shared helper is exercised
}

// TestProvisioningTerminalPathAudit is the committed enumeration required for
// "ctrld start --cd-org": every Fatal/os.Exit found by re-deriving the
// requirement (grepping commands.go's initStartCmd, cli.go's run() and its
// callers cdUIDFromProvToken/handleAPIPreflightFailure, and prog.go's
// pre-daemonization paths), reconciled against a code. None of them may
// reach a bare Fatal/os.Exit any more; each row's code is asserted against
// the known contract maps so a typo'd code name fails this test.
func TestProvisioningTerminalPathAudit(t *testing.T) {
	cases := []terminalPathCase{
		// commands.go initStartCmd (parent "ctrld start" process). v1.0 keeps
		// what master splits into commands_service_start.go in the same
		// commands.go as every other command.
		{"commands.go (initStartCmd)", "--intercept-mode is not off/dns/hard", provisionCodeInterceptModeInvalid, "TestValidateInterceptModeFlag"},
		{"commands.go (initStartCmd) / cli.go RunCobraCommand", "explicit empty --cd-org", provisionCodeProvisionTokenMalformed, "TestCheckStrFlagEmptyClassifiesEmptyCdOrg"},
		{"commands.go (initStartCmd)", "--cd/--cd-org used together with --nextdns", provisionCodeInvalidFlagCombination, "TestValidateCdAndNextDNSFlagsClassifiesConflict"},
		{"commands.go (initStartCmd)", "newService fails building the service handle", provisionCodeUnclassified, "TestStartCommandClassifiesServiceInitFailure"},
		{"commands.go (initStartCmd) / cli.go run()", "--proto is not doh/doh3 once --cd is set", provisionCodeInvalidFlagCombination, "TestValidateCdUpstreamProtocol"},
		{"commands.go (initStartCmd)", "removeServiceFlag fails while upgrading an existing service's intercept mode", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "appendServiceFlag(\"--intercept-mode\") fails during the same upgrade", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "appendServiceFlag(mode) fails during the same upgrade", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "config unmarshal fails restarting an already-installed service", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "doTasksE fails on a non-service-stage task restarting an existing service", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "socketDir() fails restarting an existing service", provisionCodeUnclassified, ""},
		// v1.0-only: the DNS intercept-mode router abstraction (predates and is
		// unrelated to issue-595) configures itself before a fresh install;
		// already routed through failRunUnclassified, not a bare fatal.
		{"commands.go (initStartCmd)", "router.ConfigureService fails configuring the router before a fresh install", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "config unmarshal fails on a fresh install", provisionCodeUnclassified, ""},
		{"commands.go (initStartCmd)", "doTasksE fails on a non-service-stage task on a fresh install", provisionCodeUnclassified, ""},

		// cli.go run() (the "ctrld run" child process --cd-org spawns, or a direct "ctrld run --cd-org" invocation)
		{"cli.go run()", "called with a nil stop channel", provisionCodeUnclassified, ""},
		{"cli.go run()", "--daemon on windows", provisionCodeUnclassified, ""},
		{"cli.go run()", "newService fails building the background service handle", provisionCodeUnclassified, ""},
		{"cli.go run()", "readBase64Config fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "config unmarshal fails", provisionCodeUnclassified, ""},
		{"cli.go run()", "network is not up", provisionCodeUnclassified, ""},
		// v1.0-only: same router abstraction as above, on the daemon side.
		{"cli.go run()", "router.PreRun fails performing the router pre-run check", provisionCodeUnclassified, ""},
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
	//   - prog.go (p *prog) setDNS() line ~962's own --intercept-mode check:
	//     explicitly left alone per T6 - it is the "runtime validation in
	//     prog.go" validInterceptMode's own doc comment calls out as distinct
	//     from "the early start command check" that got INTERCEPT_MODE_INVALID.
	//   - prog.go (p *prog) Stop() and commands.go initStartCmd's own
	//     deactivation-pin os.Exit: explicitly out of scope per the lane
	//     contract ("pin-check 126 untouched").
	//   - cli.go: doValidateCdRemoteConfig's Fatal is not reachable from the
	//     --cd-org start path at all on v1.0 - the start command defers --cd
	//     validation to processCDFlags in the "ctrld run" child instead (see
	//     the comment in initStartCmd), a divergence from master that predates
	//     and is unrelated to this lane. General CLI/config-parsing helpers
	//     (readConfigFile, processNoConfigFlags, processListenFlag,
	//     readConfigWithNotice's userHomeDir failure): these predate and apply
	//     uniformly across every ctrld invocation mode (config-file mode,
	//     no-config mode, nextdns mode), not specifically to --cd-org
	//     provisioning. Out of scope for this lane's --cd-org enumeration.
	//   - checkStrFlagEmpty for --cd (cdUidFlagName) keeps its bare fatal:
	//     only the --cd-org case above is a provisioning-token value.
	//   - cli.go uninstall()'s bare fatal on a router re-configuration
	//     failure: the "ctrld uninstall" command, not "ctrld start --cd-org".
	//
	// No firewall-mode flag exists on v1.0, so master's INTERCEPT_MODE_INVALID-
	// adjacent "--firewall-mode is not off/on" rows (parent and daemon-side)
	// have no equivalent here.
}

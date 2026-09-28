package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

// startRunFuncSource extracts the source text of initStartCmd's "Run:"
// closure body from commands.go. Driving the closure itself end-to-end for
// every early-return branch is not practical in a unit test: within a few
// lines of any check failing, it reaches into the real OS service manager.
// Some invariants about its shape are cheaper and more reliable to pin by
// reading the source than by executing it.
func startRunFuncSource(t *testing.T) string {
	t.Helper()
	file := packageSourcePath(t, "commands.go")
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("could not parse %s: %v", file, err)
	}
	var runLit *ast.FuncLit
	ast.Inspect(node, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "initStartCmd" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			// initStartCmd defines a second, unrelated "Run:" field further down
			// for a start command alias; take only the first match, which is the
			// real start command's closure this test cares about.
			if runLit == nil {
				if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "Run" {
					if lit, ok := kv.Value.(*ast.FuncLit); ok {
						runLit = lit
					}
				}
			}
			return true
		})
		return false
	})
	if runLit == nil {
		t.Fatalf("Run: func literal not found in initStartCmd in %s", file)
	}
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read %s: %v", file, err)
	}
	start := fset.Position(runLit.Body.Lbrace).Offset
	end := fset.Position(runLit.Body.Rbrace).Offset
	return string(src[start:end])
}

// TestStartCommandClearsProvisionResultBeforeAnyCheck pins the ordering fix:
// clearProvisionResult() must run before every check in the start command's
// Run closure that can fail or return early, not just before doTasksE.
// Without this, a check between the top of the closure and the old call
// sites could return early (whether by writing its own classified failure
// or, like the "service already running" and service-manager-init-error
// paths, by writing nothing at all) while a previous attempt's result file
// was still sitting there to mislead diag/postinstall on retry.
func TestStartCommandClearsProvisionResultBeforeAnyCheck(t *testing.T) {
	body := startRunFuncSource(t)

	clearIdx := strings.Index(body, "clearProvisionResult()")
	if clearIdx == -1 {
		t.Fatal("start command no longer calls clearProvisionResult()")
	}

	// Every check or step that can return out of the closure before reaching
	// doTasksE. Each must appear after the entry clear.
	earlyChecks := []string{
		"checkStrFlagEmpty(",
		"validateCdAndNextDNSFlags(",
		"validateInterceptModeFlag(",
		"doTasksE(",
	}
	for _, check := range earlyChecks {
		idx := strings.Index(body, check)
		if idx == -1 {
			t.Fatalf("expected the start command to still call %s", check)
		}
		if idx < clearIdx {
			t.Errorf("%s appears before clearProvisionResult(): a failure there could leave a stale result file behind", check)
		}
	}
}

// TestStartCommandClassifiesServiceInitFailure pins the fix for a bare
// return: when newService fails in the start command, the closure must fail
// through failProvisionUnclassified, so a result file and the identifier
// line exist, instead of a plain return that exits 0.
func TestStartCommandClassifiesServiceInitFailure(t *testing.T) {
	body := startRunFuncSource(t)
	initIdx := strings.Index(body, "newService(p, sc)")
	if initIdx == -1 {
		t.Fatal("start command no longer calls newService(p, sc)")
	}
	branchEnd := strings.Index(body[initIdx:], "p.preRun()")
	if branchEnd == -1 {
		t.Fatal("could not find the end of the service init branch")
	}
	if !strings.Contains(body[initIdx:initIdx+branchEnd], "failProvisionUnclassified(") {
		t.Error("service init failure does not fail through failProvisionUnclassified")
	}
}

// TestStartCommandReplacesStaleResultOnEarlyClassifiedFailure is a
// behavioral companion to the structural test above: it drives the real
// start command through its earliest classified failure (an invalid
// --intercept-mode) and checks the file left behind names the new attempt,
// not a stale one seeded beforehand.
func TestStartCommandReplacesStaleResultOnEarlyClassifiedFailure(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldIntercept, oldCdUID, oldCdOrg, oldNextdns := interceptMode, cdUID, cdOrg, nextdns
	t.Cleanup(func() {
		interceptMode, cdUID, cdOrg, nextdns = oldIntercept, oldCdUID, oldCdOrg, oldNextdns
	})

	// initStartCmd binds these globals to flag defaults as it registers them
	// (StringVarP writes the default straight into the pointer), so the
	// command must exist before the test overrides the values it drives the
	// closure with.
	cmd := initStartCmd()
	cdUID, cdOrg, nextdns = "", "", ""
	interceptMode = "bogus" // fails validateInterceptModeFlag before any OS work

	if err := writeProvisionResult(newProvisionResult(provisionCodeServiceStartFailed, "a previous failed attempt", nil)); err != nil {
		t.Fatal(err)
	}

	cmd.Run(cmd, nil)

	wantExit := provisionExitCodeForCode[provisionCodeInterceptModeInvalid]
	if *exitCode != wantExit {
		t.Fatalf("exit = %d, want %d (validateInterceptModeFlag should have run)", *exitCode, wantExit)
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code == string(provisionCodeServiceStartFailed) {
		t.Fatal("stale result from a previous attempt survived the new attempt")
	}
	if r.Code != string(provisionCodeInterceptModeInvalid) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeInterceptModeInvalid)
	}
}

func TestServiceStageFailureCode(t *testing.T) {
	tests := []struct {
		taskName string
		wantCode provisionFailureCode
		wantOK   bool
	}{
		{"Install", provisionCodeServiceInstall, true},
		{"Start", provisionCodeServiceStartFailed, true},
		{"Checking config", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		code, ok := serviceStageFailureCode(tc.taskName)
		if code != tc.wantCode || ok != tc.wantOK {
			t.Errorf("serviceStageFailureCode(%q) = (%q, %v), want (%q, %v)", tc.taskName, code, ok, tc.wantCode, tc.wantOK)
		}
	}
}

func stubProvisionExit(t *testing.T) *int {
	t.Helper()
	exitCode := -1
	old := provisionExit
	provisionExit = func(code int) { exitCode = code }
	t.Cleanup(func() { provisionExit = old })
	return &exitCode
}

func TestReportStartFailureUsesFreshDaemonResult(t *testing.T) {
	overrideProvisionResultPath(t)
	exitCode := stubProvisionExit(t)

	startedAt := time.Now()
	daemonResult := newProvisionResult(provisionCodeAPIUnreachable, "daemon could not reach the API", nil)
	if err := writeProvisionResult(daemonResult); err != nil {
		t.Fatal(err)
	}

	reportStartFailure(startedAt, "generic self-check failure")

	if *exitCode != provisionExitCodeForCode[provisionCodeAPIUnreachable] {
		t.Errorf("exit code = %d, want the daemon's own exit code %d", *exitCode, provisionExitCodeForCode[provisionCodeAPIUnreachable])
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != string(provisionCodeAPIUnreachable) {
		t.Errorf("persisted code = %q, want the daemon's own code untouched", out.Code)
	}
}

func TestReportStartFailureFallsBackOnStaleDaemonResult(t *testing.T) {
	overrideProvisionResultPath(t)
	exitCode := stubProvisionExit(t)

	stale := newProvisionResult(provisionCodeAPIUnreachable, "an old failure", nil)
	stale.Timestamp = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	if err := writeProvisionResult(stale); err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now()
	reportStartFailure(startedAt, "test query failed: timeout")

	if *exitCode != provisionExitCodeForCode[provisionCodeServiceSelfCheck] {
		t.Errorf("exit code = %d, want SERVICE_SELFCHECK_FAILED exit %d", *exitCode, provisionExitCodeForCode[provisionCodeServiceSelfCheck])
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != string(provisionCodeServiceSelfCheck) {
		t.Errorf("persisted code = %q, want %q", out.Code, provisionCodeServiceSelfCheck)
	}
	if out.Message != "test query failed: timeout" {
		t.Errorf("persisted message = %q, want the fallback message", out.Message)
	}
}

func TestReportStartFailureRejectsUntrustedFile(t *testing.T) {
	overrideProvisionResultPath(t)
	exitCode := stubProvisionExit(t)

	planted := newProvisionResult(provisionCodeAPIUnreachable, "planted", nil)
	planted.Code = "FAKE_CODE"
	planted.ExitCode = 99
	if err := writeProvisionResult(planted); err != nil {
		t.Fatal(err)
	}

	reportStartFailure(time.Now().Add(-time.Minute), "self-check failed")

	if *exitCode != provisionExitCodeForCode[provisionCodeServiceSelfCheck] {
		t.Errorf("exit = %d, want the fallback %d, never the planted 99", *exitCode, provisionExitCodeForCode[provisionCodeServiceSelfCheck])
	}
}

func TestReportStartFailureFallsBackWhenResultFileMissing(t *testing.T) {
	overrideProvisionResultPath(t)
	exitCode := stubProvisionExit(t)

	reportStartFailure(time.Now(), "firewall hint")

	if *exitCode != provisionExitCodeForCode[provisionCodeServiceSelfCheck] {
		t.Errorf("exit code = %d, want SERVICE_SELFCHECK_FAILED exit %d", *exitCode, provisionExitCodeForCode[provisionCodeServiceSelfCheck])
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if out.Message != "firewall hint" {
		t.Errorf("persisted message = %q, want the fallback message", out.Message)
	}
}

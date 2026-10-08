package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// startFunctionSource extracts the source text of ServiceCommand.Start's body
// from commands_service_start.go. Driving Start() itself end-to-end for every
// early-return branch is not practical in a unit test: within a few lines of
// any check failing, Start() reaches into the real OS service manager. Some
// invariants about its shape are cheaper and more reliable to pin by reading
// the source than by executing it.
func startFunctionSource(t *testing.T) string {
	t.Helper()
	file := packageSourcePath(t, "commands_service_start.go")
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("could not parse %s: %v", file, err)
	}
	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Start" || fn.Recv == nil {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("could not read %s: %v", file, err)
		}
		start := fset.Position(fn.Body.Lbrace).Offset
		end := fset.Position(fn.Body.Rbrace).Offset
		return string(src[start:end])
	}
	t.Fatalf("ServiceCommand.Start not found in %s", file)
	return ""
}

// TestServiceCommandStartClearsProvisionResultBeforeAnyCheck pins the
// ordering fix: clearProvisionResult() must run before every check in
// Start() that can fail or return early, not just before doTasksE. Without
// this, a check between the top of Start() and the old call sites could
// return early (whether by writing its own classified failure or, like the
// "service already running" and service-manager-init-error paths, by writing
// nothing at all) while a previous attempt's result file was still sitting
// there to mislead diag/postinstall on retry.
func TestServiceCommandStartClearsProvisionResultBeforeAnyCheck(t *testing.T) {
	body := startFunctionSource(t)

	clearIdx := strings.Index(body, "clearProvisionResult()")
	if clearIdx == -1 {
		t.Fatal("Start() no longer calls clearProvisionResult()")
	}

	// Every check or step that can return out of Start() before reaching
	// doTasksE. Each must appear after the entry clear.
	earlyChecks := []string{
		"checkStrFlagEmpty(",
		"validateCdAndNextDNSFlags(",
		"validateInterceptModeFlag(",
		"validateFirewallModeFlag(",
		"initializeServiceManagerWithServiceConfig(",
		"doTasksE(",
	}
	for _, check := range earlyChecks {
		idx := strings.Index(body, check)
		if idx == -1 {
			t.Fatalf("expected Start() to still call %s", check)
		}
		if idx < clearIdx {
			t.Errorf("%s appears before clearProvisionResult(): a failure there could leave a stale result file behind", check)
		}
	}
}

// TestServiceCommandStartClassifiesServiceManagerInitFailure pins the fix for
// a bare error return: a service-manager init failure in Start() must fail
// through failProvisionUnclassified, so a result file and the identifier line
// exist, instead of returning the error for a plain exit 1.
func TestServiceCommandStartClassifiesServiceManagerInitFailure(t *testing.T) {
	body := startFunctionSource(t)
	initIdx := strings.Index(body, "initializeServiceManagerWithServiceConfig(")
	if initIdx == -1 {
		t.Fatal("Start() no longer calls initializeServiceManagerWithServiceConfig")
	}
	branchEnd := strings.Index(body[initIdx:], "p.cfg = &cfg")
	if branchEnd == -1 {
		t.Fatal("could not find the end of the service-manager init branch")
	}
	branch := body[initIdx : initIdx+branchEnd]
	if !strings.Contains(branch, "failProvisionUnclassified(") {
		t.Error("service-manager init failure does not fail through failProvisionUnclassified")
	}
	if strings.Contains(branch, "return err") {
		t.Error("service-manager init failure still returns the bare error, which exits 1 with no result file")
	}
}

// startTestCommand builds the minimal cobra.Command ServiceCommand.Start needs
// before it can reach its early --intercept-mode check: the --cd/--cd-org
// flags must exist (checkStrFlagEmpty looks them up unconditionally) but stay
// unchanged, so neither Fatals.
func startTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String(cdUidFlagName, "", "")
	cmd.Flags().String(cdOrgFlagName, "", "")
	return cmd
}

// TestServiceCommandStartReplacesStaleResultOnEarlyClassifiedFailure is a
// behavioral companion to the structural test above: it drives the real
// Start() through its earliest classified failure (an invalid
// --intercept-mode) and checks the file left behind names the new attempt,
// not a stale one seeded beforehand.
func TestServiceCommandStartReplacesStaleResultOnEarlyClassifiedFailure(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldIntercept, oldNextdns, oldFirewallChanged := interceptMode, nextdns, firewallModeFlagChanged
	t.Cleanup(func() {
		interceptMode, nextdns, firewallModeFlagChanged = oldIntercept, oldNextdns, oldFirewallChanged
	})
	cdUID, cdOrg, nextdns = "", "", ""
	interceptMode = "bogus" // fails validateInterceptModeFlag before any OS work

	if err := writeProvisionResult(newProvisionResult(provisionCodeServiceStartFailed, "a previous failed attempt", nil)); err != nil {
		t.Fatal(err)
	}

	sc := NewServiceCommand()
	if err := sc.Start(startTestCommand(), nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

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

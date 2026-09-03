package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// packageSourcePath resolves a file in this package's source directory, or
// skips the test when the source is not available. The Windows CI job runs
// pre-built test binaries with no checkout, so neither the working directory
// nor the build-time path recorded by runtime.Caller reaches the source
// there. Skipping is safe for these static checks: they analyze the same
// source on every platform, and the jobs with a checkout still enforce them.
func packageSourcePath(t *testing.T, name string) string {
	t.Helper()
	if _, err := os.Stat(name); err == nil {
		return name
	}
	if _, thisFile, _, ok := runtime.Caller(0); ok {
		p := filepath.Join(filepath.Dir(thisFile), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("package source for %s not available (pre-built test binary without a checkout); this static check runs where source is present", name)
	return ""
}

// provisionBoundaryFiles are the files this lane's provisioning-hardening
// work audited: every terminal path they can reach must report a classified
// failure (a result file, an output line, a stage-scoped exit code), not a
// bare crash installer tooling cannot read. TestProvisioningTerminalPathAudit
// documents the audit by scenario; this test enforces it structurally so a
// later change cannot reintroduce a bare fatal without either classifying it
// or adding it here with a reason.
//
// Scope: the check sees direct calls (".Fatal()", "os.Exit", "panic") in the
// files listed here. A helper defined in one of these files is caught once,
// at the body that holds the call, so an indirect exit through it needs no
// second rule. A helper defined outside the list, such as
// checkHasElevatedPrivilege in service.go wired as the "start" PreRun, is
// outside the reach of this check. TestProvisioningTerminalPathAudit lists
// those by hand in its exclusion comment.
var provisionBoundaryFiles = []string{
	"cli.go",
	"commands_service_start.go",
	"commands_run.go",
	"prog.go",
	"provision_result.go",
}

// provisionBoundaryFatalAllowlist is every call in the files above that
// still reaches a bare ".Fatal()" (on any logger chain), "os.Exit", or
// "panic", keyed
// by "file.go:FuncName" (FuncName includes the receiver type for methods,
// e.g. "prog.setDNS"). Each entry names why it is not a provisioning
// failure, or why it predates and sits outside the --cd-org boundary this
// lane hardened.
var provisionBoundaryFatalAllowlist = map[string]string{
	"cli.go:RunMobile": `panic on a nil AppConfig is a programming error in the mobile host ` +
		`app, at an entry point the CLI command tree never calls. Not reachable from ` +
		`"ctrld start --cd-org".`,

	"cli.go:run": `os.Exit(0) is the successful exit of the daemon-respawn launcher, right ` +
		`after it starts the real background process. Not a failure.`,

	"cli.go:readConfigFile": `shared CLI config-parsing helper used the same way by every ` +
		`invocation mode (config-file, no-config, nextdns, --cd, --cd-org). Predates and is ` +
		`orthogonal to the --cd-org provisioning boundary.`,

	"cli.go:processNoConfigFlags": `shared CLI helper enforcing --listen/--primary_upstream in ` +
		`no-config mode. Applies uniformly across every invocation mode, not specifically to ` +
		`provisioning.`,

	"cli.go:processListenFlag": `shared CLI helper parsing --listen. Applies uniformly across ` +
		`every invocation mode, not specifically to provisioning.`,

	"cli.go:readConfigWithNotice": `shared CLI helper (userHomeDir failure while locating the ` +
		`default config file). Applies uniformly across every invocation mode, not specifically ` +
		`to provisioning.`,

	"cli.go:checkStrFlagEmpty": `shared flag-emptiness helper. Only an explicit empty --cd-org ` +
		`is a provisioning-token value, classified separately inside this function; every other ` +
		`flag (currently --cd) keeps its bare fatal.`,

	"commands_service_start.go:ServiceCommand.Start": `the deactivation pin check's ` +
		`os.Exit(126). Out of scope for this lane by contract ("pin-check 126 untouched").`,

	"prog.go:prog.Stop": `the deactivation pin check's os.Exit(126). Out of scope for this ` +
		`lane by contract ("pin-check 126 untouched").`,

	"prog.go:prog.setDNS": `the runtime --intercept-mode validation (validInterceptMode), ` +
		`distinct from the early "ctrld start" check that already reports ` +
		`INTERCEPT_MODE_INVALID. Left alone per T6's own doc comment.`,
}

// funcDeclKey names a function declaration the way
// provisionBoundaryFatalAllowlist keys it: "FuncName" for a plain function,
// "ReceiverType.FuncName" for a method.
func funcDeclKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recvType := fn.Recv.List[0].Type
	if star, ok := recvType.(*ast.StarExpr); ok {
		recvType = star.X
	}
	if ident, ok := recvType.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// isBareFatalOrExitCall reports whether call is "<expr>.Fatal(...)" on any
// logger chain, "os.Exit(...)", or a bare "panic(...)".
func isBareFatalOrExitCall(call *ast.CallExpr) bool {
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name == "Fatal" {
		return true
	}
	if sel.Sel.Name == "Exit" {
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" {
			return true
		}
	}
	return false
}

// TestProvisionBoundaryHasNoUnlistedBareFatal parses every provisioning
// boundary file and flags a bare Fatal/os.Exit that is not in the allowlist
// above. A new one appearing here means a change added a crash the
// provisioning boundary's contract does not allow: classify it through
// failProvision/failProvisionUnclassified, or add it to the allowlist with a
// reason if it genuinely sits outside the boundary.
func TestProvisionBoundaryHasNoUnlistedBareFatal(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range provisionBoundaryFiles {
		node, err := parser.ParseFile(fset, packageSourcePath(t, file), nil, 0)
		if err != nil {
			t.Fatalf("could not parse %s: %v", file, err)
		}
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := file + ":" + funcDeclKey(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isBareFatalOrExitCall(call) {
					return true
				}
				if _, allowed := provisionBoundaryFatalAllowlist[key]; !allowed {
					pos := fset.Position(call.Pos())
					t.Errorf("%s:%d: unlisted bare fatal/exit in %s - classify it through "+
						"failProvision/failProvisionUnclassified, or add it to "+
						"provisionBoundaryFatalAllowlist with a reason", file, pos.Line, key)
				}
				return true
			})
		}
	}
}

// TestProvisionBoundaryAllowlistHasNoStaleEntries is the converse check: every
// allowlisted key must still name a real bare Fatal/os.Exit. A stale entry
// (the call was removed or reclassified) would silently widen the allowlist
// and hide a real regression the next time this test runs.
func TestProvisionBoundaryAllowlistHasNoStaleEntries(t *testing.T) {
	fset := token.NewFileSet()
	found := make(map[string]bool, len(provisionBoundaryFatalAllowlist))
	for _, file := range provisionBoundaryFiles {
		node, err := parser.ParseFile(fset, packageSourcePath(t, file), nil, 0)
		if err != nil {
			t.Fatalf("could not parse %s: %v", file, err)
		}
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := file + ":" + funcDeclKey(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isBareFatalOrExitCall(call) {
					return true
				}
				found[key] = true
				return true
			})
		}
	}
	for key := range provisionBoundaryFatalAllowlist {
		if !found[key] {
			t.Errorf("provisionBoundaryFatalAllowlist[%q] no longer matches any bare fatal/exit; remove the stale entry", key)
		}
	}
}

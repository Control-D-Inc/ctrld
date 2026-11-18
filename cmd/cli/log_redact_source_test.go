package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// packageSourceDir returns the directory that holds this test file, or false
// when the test binary runs without its source tree. It looks for this file
// itself, so a stray .go file in the working directory is not read as the
// source of this package.
func packageSourceDir() (string, bool) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", false
	}
	if _, err := os.Stat(filepath.Base(thisFile)); err == nil {
		return ".", true
	}
	if _, err := os.Stat(thisFile); err == nil {
		return filepath.Dir(thisFile), true
	}
	return "", false
}

// The redaction holds only while every core of the logger writes through
// newLogSink, and while every change of cdUID or cdOrg reaches the copy that
// the step reads. A new call site that skips either still compiles, so this
// test reads the source of every platform.
func Test_sourceKeepsEveryLogLineBehindTheRedaction(t *testing.T) {
	sourceDir, ok := packageSourceDir()
	if !ok {
		t.Skip("the test binary runs without its source tree, so there is no source to read")
	}
	files, err := filepath.Glob(filepath.Join(sourceDir, "*.go"))
	if err != nil {
		t.Fatalf("list the source files: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				checkLogRedactionNode(t, fset, fn.Name.Name, n)
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("the test read no source file")
	}
}

// secretSetters may assign cdUID or cdOrg, because each of them stores the
// copy that the redaction reads.
var secretSetters = map[string]bool{"setCdUID": true, "applyAppConfig": true}

// unredactedCoreBuilders may build a core with no redaction step.
// renderLogHeader writes into a buffer that it redacts itself.
var unredactedCoreBuilders = map[string]bool{"renderLogHeader": true}

func checkLogRedactionNode(t *testing.T, fset *token.FileSet, funcName string, n ast.Node) {
	t.Helper()
	switch node := n.(type) {
	case *ast.CallExpr:
		if isSelectorCall(node, "zapcore", "NewCore") && len(node.Args) == 3 &&
			!isCallTo(node.Args[1], "newLogSink") && !unredactedCoreBuilders[funcName] {
			t.Errorf("%s: %s builds a zap core that skips newLogSink", fset.Position(node.Pos()), funcName)
		}
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Output" && len(node.Args) == 1 {
			if pkg, ok := sel.X.(*ast.CallExpr); ok && isMainLogLoad(pkg) {
				t.Errorf("%s: %s sets a logger output that skips newLogSink", fset.Position(node.Pos()), funcName)
			}
		}
	case *ast.AssignStmt:
		for _, lhs := range node.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || (ident.Name != "cdUID" && ident.Name != "cdOrg") || secretSetters[funcName] {
				continue
			}
			t.Errorf("%s: %s assigns %s; call setCdUID or storeLogSecrets, so the redaction knows the value", fset.Position(node.Pos()), funcName, ident.Name)
		}
	}
}

func isSelectorCall(call *ast.CallExpr, pkgName, funcName string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != funcName {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == pkgName
}

// isMainLogLoad matches mainLog.Load().
func isMainLogLoad(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Load" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "mainLog"
}

func isCallTo(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == name
}

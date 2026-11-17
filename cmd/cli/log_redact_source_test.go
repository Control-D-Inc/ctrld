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

// The redaction holds only while every logger output passes newLogOutput,
// and while every change of cdUID or cdOrg reaches the copy that the step
// reads. A new call site that skips either still compiles, so this test reads
// the source of every platform.
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

func checkLogRedactionNode(t *testing.T, fset *token.FileSet, funcName string, n ast.Node) {
	t.Helper()
	switch node := n.(type) {
	case *ast.CallExpr:
		if isLoggerOutputCall(node) && !isCallTo(node.Args[0], "newLogOutput") {
			t.Errorf("%s: %s sets a logger output that skips newLogOutput", fset.Position(node.Pos()), funcName)
		}
		if isZerologNew(node) && !isDiscard(node.Args[0]) && !isCallTo(node.Args[0], "newLogOutput") && funcName != "renderLogHeader" {
			t.Errorf("%s: %s builds a zerolog logger that skips newLogOutput", fset.Position(node.Pos()), funcName)
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

// isLoggerOutputCall matches x.Output(w). exec.Cmd.Output takes no argument.
func isLoggerOutputCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Output" && len(call.Args) == 1
}

func isZerologNew(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" || len(call.Args) != 1 {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "zerolog"
}

func isCallTo(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == name
}

func isDiscard(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Discard" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "io"
}

package ctrld

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The mobile tests can only see a read of the OS that goes through osinfoNew.
// A direct call of osinfo starts sw_vers with an absolute path, which no fake
// in PATH can catch, so only os_version.go may call the osinfo functions.
func TestOnlyTheSeamCallsOsinfo(t *testing.T) {
	const osinfoPath = "github.com/cuonglm/osinfo"
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "os_version.go" {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		localName := ""
		for _, imp := range file.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path != osinfoPath {
				continue
			}
			localName = "osinfo"
			if imp.Name != nil {
				localName = imp.Name.Name
			}
		}
		if localName == "" {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != localName {
				return true
			}
			if sel.Sel.Name == "New" || sel.Sel.Name == "Release" {
				t.Errorf("%s calls osinfo.%s directly; use osinfoNew, OSVersion, or osDist", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

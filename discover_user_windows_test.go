//go:build windows

package ctrld

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
)

// Every procedure that console-session discovery loads at runtime must exist in
// the DLL it is loaded from. A wrong DLL makes Find fail on every host, so
// discovery silently reports no user instead of the signed-in one.
func TestConsoleSessionProceduresResolve(t *testing.T) {
	for _, p := range []interface {
		Find() error
	}{procWTSQuerySessionInformation, procWTSFreeMemory} {
		if err := p.Find(); err != nil {
			t.Fatalf("console session procedure does not resolve: %v", err)
		}
	}
}

// discoverSessionUser must agree with Windows' own view of the console session:
// the user shown on the active "console" row of `query user`, or no user when
// that row is absent.
func TestDiscoverSessionUserMatchesConsoleSession(t *testing.T) {
	quser, err := exec.LookPath("quser.exe")
	if err != nil {
		t.Skip("quser.exe not available")
	}
	// quser exits 1 when no session exists; its output still answers the question.
	out, _ := exec.Command(quser).CombinedOutput()
	want := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(strings.TrimPrefix(sc.Text(), ">"))
		if len(f) >= 4 && strings.EqualFold(f[1], "console") && strings.EqualFold(f[3], "Active") {
			want = f[0]
		}
	}
	got := discoverSessionUser(context.Background())
	if !strings.EqualFold(got, want) {
		t.Fatalf("discoverSessionUser() = %q, want %q (quser output: %q)", got, want, out)
	}
}

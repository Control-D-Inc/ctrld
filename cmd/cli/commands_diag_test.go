package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// fakeProvisionToken stands in for a real provisioning code. Tests assert it
// never reaches either output mode.
const fakeProvisionToken = "org-v1-FAKE00000000000000000000TOKEN"

func withManagedPrefsSeam(t *testing.T, supported bool, values map[string]string) {
	t.Helper()
	oldSupported := managedPrefsSupported
	oldRead := managedPrefsRead
	managedPrefsSupported = func() bool { return supported }
	managedPrefsRead = func(_ context.Context, _, key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	}
	t.Cleanup(func() {
		managedPrefsSupported = oldSupported
		managedPrefsRead = oldRead
	})
}

// overrideDiagProvisionResultPath points the writer and diag at one temp
// file, so a test can write a result and read it back through diag.
func overrideDiagProvisionResultPath(t *testing.T) string {
	t.Helper()
	path := overrideProvisionResultPath(t)
	old := diagProvisionResultPath
	diagProvisionResultPath = func() string { return path }
	t.Cleanup(func() { diagProvisionResultPath = old })
	return path
}

func withServiceStateSeam(t *testing.T, state diagServiceState) {
	t.Helper()
	old := diagServiceStateFn
	diagServiceStateFn = func() diagServiceState { return state }
	t.Cleanup(func() { diagServiceStateFn = old })
}

func withAPIProbeSeam(t *testing.T, err error) {
	t.Helper()
	old := diagProbeReachability
	diagProbeReachability = func(context.Context, bool) error { return err }
	t.Cleanup(func() { diagProbeReachability = old })
}

func seedTrustedProvisionResult(t *testing.T, age time.Duration) {
	t.Helper()
	overrideDiagProvisionResultPath(t)
	r := newProvisionResult(provisionCodeTokenExpired, "the provisioning code has expired", nil)
	r.Timestamp = time.Now().Add(-age).UTC().Format(time.RFC3339)
	if err := writeProvisionResult(r); err != nil {
		t.Fatal(err)
	}
}

// seedOversizedProvisionResult writes a trusted result file straight to disk
// (bypassing newProvisionResult's own bounding), standing in for a file left
// by a mismatched or tampered version of ctrld.
func seedOversizedProvisionResult(t *testing.T) {
	t.Helper()
	overrideDiagProvisionResultPath(t)
	attempts := make([]provisionBindAttempt, maxProvisionBindAttempts*3)
	for i := range attempts {
		attempts[i] = provisionBindAttempt{
			Addr:    "0.0.0.0:53",
			Proto:   "udp",
			OSError: strings.Repeat("e", diagFieldMaxLen*3),
		}
	}
	r := &provisionResult{
		Version:   1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Stage:     string(provisionStageListener),
		Code:      string(provisionCodeListenerBindFailed),
		ExitCode:  provisionExitCodeForCode[provisionCodeListenerBindFailed],
		Message:   strings.Repeat("m", diagFieldMaxLen*3),
		Detail:    &provisionDetail{Attempts: attempts},
	}
	if err := writeProvisionResult(r); err != nil {
		t.Fatal(err)
	}
}

func TestDiagProvisionResultBoundsOversizedFields(t *testing.T) {
	seedOversizedProvisionResult(t)

	got := collectProvisionResultDiag()

	if n := utf8.RuneCountInString(got.Message); n > diagFieldMaxLen {
		t.Errorf("message length = %d, want <= %d", n, diagFieldMaxLen)
	}
	if len(got.Attempts) > maxProvisionBindAttempts {
		t.Errorf("attempts length = %d, want <= %d", len(got.Attempts), maxProvisionBindAttempts)
	}
	for _, a := range got.Attempts {
		if n := utf8.RuneCountInString(a.OSError); n > diagFieldMaxLen {
			t.Errorf("attempt os_error length = %d, want <= %d", n, diagFieldMaxLen)
		}
	}
}

func TestDiagTextReportNeverLeaksToken(t *testing.T) {
	withManagedPrefsSeam(t, true, map[string]string{
		"":               "", // domain probe: profile present
		"ProvisionToken": fakeProvisionToken,
		"CustomHostname": "corp-laptop.example.com",
		"InterceptMode":  "intercept-dns",
	})
	seedTrustedProvisionResult(t, 3*time.Minute+12*time.Second)
	withServiceStateSeam(t, diagServiceState{Status: "stopped"})
	withAPIProbeSeam(t, nil)

	report := buildDiagReport(context.Background())
	var buf bytes.Buffer
	renderDiagText(&buf, report)
	out := buf.String()

	if strings.Contains(out, fakeProvisionToken) {
		t.Fatalf("text output leaked the provision token: %s", out)
	}
	wantLines := []string{
		"provision token: present",
		"custom hostname: corp-laptop.example.com",
		"intercept mode: intercept-dns",
		"stage: bootstrap",
		"code: TOKEN_EXPIRED",
		"exit code: 34",
		"status: stopped",
		"reachable: true",
	}
	for _, want := range wantLines {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q, got:\n%s", want, out)
		}
	}
}

func TestDiagJSONReportNeverLeaksToken(t *testing.T) {
	withManagedPrefsSeam(t, true, map[string]string{
		"":               "",
		"ProvisionToken": fakeProvisionToken,
		"CustomHostname": "corp-laptop.example.com",
		"InterceptMode":  "standard",
	})
	seedTrustedProvisionResult(t, time.Minute)
	withServiceStateSeam(t, diagServiceState{Status: "running"})
	withAPIProbeSeam(t, errors.New("dial tcp: connect: connection refused"))

	report := buildDiagReport(context.Background())
	var buf bytes.Buffer
	if err := writeDiagJSON(&buf, report); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, fakeProvisionToken) {
		t.Fatalf("JSON output leaked the provision token: %s", out)
	}

	var decoded diagReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("could not decode JSON report: %v", err)
	}
	if decoded.ManagedPreferences.ProvisionToken != "present" {
		t.Errorf("provision_token = %q, want present", decoded.ManagedPreferences.ProvisionToken)
	}
	if decoded.ManagedPreferences.CustomHostname != "corp-laptop.example.com" {
		t.Errorf("custom_hostname = %q", decoded.ManagedPreferences.CustomHostname)
	}
	if decoded.ProvisionResult.Status != "recorded" || decoded.ProvisionResult.Code != "TOKEN_EXPIRED" {
		t.Errorf("provision_result = %+v", decoded.ProvisionResult)
	}
	if decoded.ServiceState.Status != "running" {
		t.Errorf("service_state = %+v", decoded.ServiceState)
	}
	if decoded.APIReachability.Reachable {
		t.Error("api_reachability.reachable = true, want false")
	}
	if decoded.APIReachability.ErrorClass == "" {
		t.Error("api_reachability.error_class empty for an unreachable API")
	}
}

func TestDiagEmptyMachine(t *testing.T) {
	overrideDiagProvisionResultPath(t) // temp dir, no result file written
	withManagedPrefsSeam(t, false, nil)
	withServiceStateSeam(t, diagServiceState{Status: "not_installed"})
	withAPIProbeSeam(t, context.DeadlineExceeded)

	report := buildDiagReport(context.Background())

	if report.ManagedPreferences.Applicable {
		t.Error("managed preferences reported applicable with no profile on this platform")
	}
	if report.ProvisionResult.Status != "none" {
		t.Errorf("provision result status = %q, want none", report.ProvisionResult.Status)
	}
	if report.ServiceState.Status != "not_installed" {
		t.Errorf("service state = %q, want not_installed", report.ServiceState.Status)
	}
	if report.APIReachability.Reachable {
		t.Error("api reachability reported reachable with a forced timeout")
	}
	if report.APIReachability.ErrorClass != "timeout" {
		t.Errorf("error class = %q, want timeout", report.APIReachability.ErrorClass)
	}

	var buf bytes.Buffer
	renderDiagText(&buf, report)
	if !strings.Contains(buf.String(), "none recorded") {
		t.Errorf("text output missing 'none recorded': %s", buf.String())
	}
}

// Without root, diag must look where the root-run service wrote the result
// file, not in the home directory of the current user.
func TestDiagProvisionResultPathIgnoresUserHome(t *testing.T) {
	want := "/etc/controld/" + provisionResultFileName
	if runtime.GOOS == "windows" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		want = filepath.Join(filepath.Dir(exe), provisionResultFileName)
	}
	if got := diagProvisionResultPath(); got != want {
		t.Errorf("diag provision result path = %q, want %q", got, want)
	}
}

// Diag must read where a daemon started with --homedir wrote, so it obeys
// the same override as the writer.
func TestDiagProvisionResultPathHonorsHomedir(t *testing.T) {
	old := homedir
	homedir = t.TempDir()
	t.Cleanup(func() { homedir = old })
	want := filepath.Join(homedir, provisionResultFileName)
	if got := diagProvisionResultPath(); got != want {
		t.Errorf("diag provision result path = %q, want %q", got, want)
	}
}

// A result file the current user cannot read must report that, not
// "corrupt": the file is fine, the reader lacks root.
func TestDiagProvisionResultUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 file")
	}
	path := overrideDiagProvisionResultPath(t)
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}

	r := collectProvisionResultDiag()
	if r.Status != "unreadable" {
		t.Errorf("status = %q, want unreadable", r.Status)
	}
	if r.AgeSeconds != -1 {
		t.Errorf("age_seconds = %d, want -1", r.AgeSeconds)
	}

	var buf bytes.Buffer
	renderDiagText(&buf, diagReport{ProvisionResult: r})
	if !strings.Contains(buf.String(), "permission denied ("+diagElevateHint()+")") {
		t.Errorf("text output does not name permission denied and the elevation step: %s", buf.String())
	}
}

func TestDiagServiceStateHangYieldsTimeout(t *testing.T) {
	old := diagServiceStateFn
	// started closes the instant the background probe goroutine reads and
	// invokes our stub. Cleanup waits for that before restoring the global:
	// otherwise a slow-to-schedule goroutine can still be reading
	// diagServiceStateFn when Cleanup writes to it, a data race on the shared
	// package var (this test's stub is left running past the test's own
	// return, same as production - see collectServiceStateBounded's doc).
	started := make(chan struct{})
	diagServiceStateFn = func() diagServiceState {
		close(started)
		time.Sleep(2 * time.Second) // stand in for a wedged systemctl/launchctl
		return diagServiceState{Status: "running"}
	}
	t.Cleanup(func() {
		<-started
		diagServiceStateFn = old
	})

	withManagedPrefsSeam(t, false, nil)
	overrideDiagProvisionResultPath(t)
	withAPIProbeSeam(t, nil)

	// A short deadline stands in for the overall 15s budget already having
	// run low; the probe must still yield within it instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	report := buildDiagReport(ctx)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("buildDiagReport took %s, want bounded well under the 2s hang", elapsed)
	}
	if report.ServiceState.Status != "unknown" {
		t.Errorf("service state status = %q, want unknown", report.ServiceState.Status)
	}
	if !strings.Contains(report.ServiceState.Note, "timed out") {
		t.Errorf("service state note = %q, want it to mention timing out", report.ServiceState.Note)
	}
}

func TestDiagManagedPrefsProfileAbsent(t *testing.T) {
	withManagedPrefsSeam(t, true, map[string]string{}) // domain read fails: profile absent
	m := collectManagedPreferences(context.Background())
	if m.ProfilePresent {
		t.Error("profile reported present when the domain read failed")
	}
	if m.Note == "" {
		t.Error("expected a note explaining the absent profile")
	}
}

func TestDiagManagedPrefsTokenAbsent(t *testing.T) {
	withManagedPrefsSeam(t, true, map[string]string{"": ""}) // profile present, no keys set
	m := collectManagedPreferences(context.Background())
	if !m.ProfilePresent {
		t.Fatal("profile should be present")
	}
	if m.ProvisionToken != "absent" {
		t.Errorf("provision token = %q, want absent", m.ProvisionToken)
	}
}

// An empty ProvisionToken value must read as absent: the postinstall refuses
// to provision on an empty token, so diag must not call it present.
func TestDiagManagedPrefsTokenEmpty(t *testing.T) {
	withManagedPrefsSeam(t, true, map[string]string{"": "", "ProvisionToken": ""})
	m := collectManagedPreferences(context.Background())
	if !m.ProfilePresent {
		t.Fatal("profile should be present")
	}
	if m.ProvisionToken != "absent" {
		t.Errorf("provision token = %q, want absent", m.ProvisionToken)
	}
}

func TestClassifyReachabilityError(t *testing.T) {
	if got := classifyReachabilityError(nil); got != "" {
		t.Errorf("nil error class = %q, want empty", got)
	}
	if got := classifyReachabilityError(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("deadline exceeded class = %q, want timeout", got)
	}
}

func TestDiagCommandJSONFlag(t *testing.T) {
	withManagedPrefsSeam(t, false, nil)
	overrideDiagProvisionResultPath(t)
	withServiceStateSeam(t, diagServiceState{Status: "not_installed"})
	withAPIProbeSeam(t, nil)

	rootCmd := &cobra.Command{Use: "ctrld"}
	InitDiagCmd(rootCmd)
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"diag", "--json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diag --json returned error: %v", err)
	}
	var decoded diagReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("diag --json did not print valid JSON: %v\n%s", err, buf.String())
	}
}

// writerFailingAfter accepts the first n bytes written to it, then fails
// every write after that - standing in for a pipe closed by a downstream
// reader (`ctrld diag --json | head -1`).
type writerFailingAfter struct {
	n       int
	written int
}

func (w *writerFailingAfter) Write(p []byte) (int, error) {
	if w.written >= w.n {
		return 0, errors.New("write: broken pipe")
	}
	remaining := w.n - w.written
	if len(p) > remaining {
		w.written += remaining
		return remaining, errors.New("write: broken pipe")
	}
	w.written += len(p)
	return len(p), nil
}

func TestDiagJSONWriteErrorStillExitsZero(t *testing.T) {
	withManagedPrefsSeam(t, false, nil)
	overrideDiagProvisionResultPath(t)
	withServiceStateSeam(t, diagServiceState{Status: "not_installed"})
	withAPIProbeSeam(t, nil)

	rootCmd := &cobra.Command{Use: "ctrld"}
	InitDiagCmd(rootCmd)
	rootCmd.SetOut(&writerFailingAfter{n: 10})
	rootCmd.SetArgs([]string{"diag", "--json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diag --json with a failing writer returned error %v, want nil per the always-exit-0 contract", err)
	}
}

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func overrideProvisionResultPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), provisionResultFileName)
	old := provisionResultPath
	provisionResultPath = func() string { return path }
	t.Cleanup(func() { provisionResultPath = old })
	return path
}

// The result file must obey the same homedir override as the log and the
// config file, so a daemon started with --homedir writes it next to them.
func TestProvisionResultPathHonorsHomedir(t *testing.T) {
	old := homedir
	homedir = t.TempDir()
	t.Cleanup(func() { homedir = old })
	want := filepath.Join(homedir, provisionResultFileName)
	if got := provisionResultPath(); got != want {
		t.Errorf("provisionResultPath() = %q, want %q", got, want)
	}
}

func TestProvisionCodesMapToOneStageAndInRangeExit(t *testing.T) {
	stageRanges := map[provisionStage][2]int{
		provisionStageInput:     {20, 29},
		provisionStageBootstrap: {30, 39},
		provisionStageListener:  {40, 49},
		provisionStageService:   {50, 59},
	}
	reservedExits := map[int]string{
		statusExitRunning:              "ctrld status running",
		statusExitStopped:              "ctrld status stopped",
		statusExitUnknown:              "ctrld status unknown",
		statusExitNotReady:             "ctrld status not ready",
		deactivationPinInvalidExitCode: "deactivation pin invalid",
	}
	seenExits := make(map[int]provisionFailureCode)
	for _, code := range allProvisionFailureCodes {
		stage, ok := provisionStageForCode[code]
		if !ok {
			t.Fatalf("code %s has no stage", code)
		}
		exit, ok := provisionExitCodeForCode[code]
		if !ok {
			t.Fatalf("code %s has no exit code", code)
		}
		r := stageRanges[stage]
		if exit < r[0] || exit > r[1] {
			t.Errorf("code %s exit %d outside stage %s range %v", code, exit, stage, r)
		}
		if owner, ok := reservedExits[exit]; ok {
			t.Errorf("code %s exit %d collides with %s", code, exit, owner)
		}
		if prev, dup := seenExits[exit]; dup {
			t.Errorf("codes %s and %s share exit %d", prev, code, exit)
		}
		seenExits[exit] = code
	}
	if len(allProvisionFailureCodes) != 17 {
		t.Errorf("expected 17 codes, got %d", len(allProvisionFailureCodes))
	}
}

func TestNewProvisionResultRedactsSecrets(t *testing.T) {
	token := "org-secret-token-12345"
	cdUIDValue := "abcdef123456"
	attempts := []provisionBindAttempt{
		{Addr: "127.0.0.1:53", Proto: "udp", OSError: "bind failed for " + token},
	}
	r := newProvisionResult(
		provisionCodeListenerBindFailed,
		"could not bind, token="+token+" uid="+cdUIDValue,
		attempts,
		token, cdUIDValue,
	)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, cdUIDValue} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("serialized result contains secret %q: %s", secret, raw)
		}
	}
}

func TestNewProvisionResultBoundsDetail(t *testing.T) {
	long := strings.Repeat("x", 1000)
	var attempts []provisionBindAttempt
	for i := 0; i < 50; i++ {
		attempts = append(attempts, provisionBindAttempt{Addr: long, Proto: "udp", OSError: long})
	}
	r := newProvisionResult(provisionCodeListenerBindFailed, long, attempts)
	if got := len(r.Detail.Attempts); got > maxProvisionBindAttempts {
		t.Errorf("attempts not capped: %d > %d", got, maxProvisionBindAttempts)
	}
	if len(r.Message) > maxProvisionStringLen {
		t.Errorf("message not capped: %d", len(r.Message))
	}
	for _, a := range r.Detail.Attempts {
		if len(a.Addr) > maxProvisionStringLen || len(a.OSError) > maxProvisionStringLen {
			t.Error("attempt fields not capped")
		}
	}
}

func TestProvisionResultFields(t *testing.T) {
	r := newProvisionResult(provisionCodeAPIRejected, "the API rejected this configuration", nil)
	if r.Version != 1 {
		t.Errorf("version = %d, want 1", r.Version)
	}
	if r.Stage != string(provisionStageBootstrap) {
		t.Errorf("stage = %q, want bootstrap", r.Stage)
	}
	if r.ExitCode != provisionExitCodeForCode[provisionCodeAPIRejected] {
		t.Errorf("exit = %d", r.ExitCode)
	}
	if _, err := time.Parse(time.RFC3339, r.Timestamp); err != nil {
		t.Errorf("timestamp %q not RFC3339: %v", r.Timestamp, err)
	}
	if r.Detail != nil {
		t.Error("nil attempts should give nil detail")
	}
}

func TestProvisionResultTrusted(t *testing.T) {
	good := newProvisionResult(provisionCodeListenerBindFailed, "x", nil)
	if !provisionResultTrusted(good) {
		t.Error("constructor-built result must be trusted")
	}
	bogusCode := newProvisionResult(provisionCodeListenerBindFailed, "x", nil)
	bogusCode.Code = "TOTALLY_MADE_UP"
	if provisionResultTrusted(bogusCode) {
		t.Error("unknown code must not be trusted")
	}
	wrongExit := newProvisionResult(provisionCodeListenerBindFailed, "x", nil)
	wrongExit.ExitCode = 126
	if provisionResultTrusted(wrongExit) {
		t.Error("exit code not matching the contract must not be trusted")
	}
	wrongStage := newProvisionResult(provisionCodeListenerBindFailed, "x", nil)
	wrongStage.Stage = string(provisionStageService)
	if provisionResultTrusted(wrongStage) {
		t.Error("stage not matching the code must not be trusted")
	}
}

func TestNewProvisionResultTruncatesOnRuneBoundary(t *testing.T) {
	msg := strings.Repeat("é", maxProvisionStringLen) // 2 bytes per rune
	r := newProvisionResult(provisionCodeListenerBindFailed, msg, nil)
	if len(r.Message) > maxProvisionStringLen {
		t.Errorf("message not capped: %d bytes", len(r.Message))
	}
	if !utf8.ValidString(r.Message) {
		t.Error("truncation split a multi-byte rune")
	}
}

func TestFailureCodeDocTableMatchesConstants(t *testing.T) {
	buf, err := os.ReadFile(filepath.Join("..", "..", "docs", "provisioning-failure-codes.md"))
	if os.IsNotExist(err) {
		// The Windows CI runner executes prebuilt test binaries outside the
		// repo; the sync guarantee is still enforced on runners with a checkout.
		t.Skip("failure-code doc not available in this test environment")
	}
	if err != nil {
		t.Fatalf("could not read the failure-code doc: %v", err)
	}
	doc := string(buf)
	// Package-stage rows document identifiers scripts/pkg/postinstall emits
	// on its own; they are not in this binary's failure-code registry, so
	// they sit outside the one-row-per-code count below.
	rows := 0
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| `") && !strings.Contains(line, "| package |") {
			rows++
		}
	}
	if rows != len(allProvisionFailureCodes) {
		t.Errorf("doc table has %d non-package code rows, want %d", rows, len(allProvisionFailureCodes))
	}
	for _, code := range allProvisionFailureCodes {
		row := "| `" + string(code) + "` | " + string(provisionStageForCode[code]) + " | " + strconv.Itoa(provisionExitCodeForCode[code]) + " |"
		if !strings.Contains(doc, row) {
			t.Errorf("doc table missing row for %s (want prefix %q)", code, row)
		}
	}
}

func TestProvisionFailureLineFormat(t *testing.T) {
	r := newProvisionResult(provisionCodeListenerBindFailed, "could not find available listen ip and port", nil)
	want := "provisioning failed: stage=listener code=LISTENER_BIND_FAILED (exit 41)"
	if got := r.failureLine(); got != want {
		t.Errorf("failureLine() = %q, want %q", got, want)
	}
}

func TestProvisionResultRoundTrip(t *testing.T) {
	overrideProvisionResultPath(t)
	in := newProvisionResult(provisionCodeServiceStartFailed, "service failed to start", nil)
	if err := writeProvisionResult(in); err != nil {
		t.Fatal(err)
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != in.Code || out.Stage != in.Stage || out.ExitCode != in.ExitCode || out.Message != in.Message {
		t.Errorf("round trip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestWriteProvisionResultOverwritesAtomically(t *testing.T) {
	path := overrideProvisionResultPath(t)
	first := newProvisionResult(provisionCodeAPIUnreachable, "first", nil)
	if err := writeProvisionResult(first); err != nil {
		t.Fatal(err)
	}
	second := newProvisionResult(provisionCodeListenerBindFailed, "second", nil)
	if err := writeProvisionResult(second); err != nil {
		t.Fatal(err)
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != string(provisionCodeListenerBindFailed) || out.Message != "second" {
		t.Errorf("overwrite failed: %+v", out)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestClearProvisionResult(t *testing.T) {
	path := overrideProvisionResultPath(t)
	clearProvisionResult() // missing file must not panic or error loudly
	if err := writeProvisionResult(newProvisionResult(provisionCodeAPIUnreachable, "x", nil)); err != nil {
		t.Fatal(err)
	}
	clearProvisionResult()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("result file still present after clear: %v", err)
	}
}

func TestReadProvisionResultMissing(t *testing.T) {
	overrideProvisionResultPath(t)
	if _, err := readProvisionResult(); err == nil {
		t.Error("expected error reading missing result file")
	}
}

func TestFailProvisionWritesLogsNotifiesAndExits(t *testing.T) {
	overrideProvisionResultPath(t)
	exitCode := -1
	oldExit := provisionExit
	provisionExit = func(code int) { exitCode = code }
	t.Cleanup(func() { provisionExit = oldExit })

	notified := false
	r := newProvisionResult(provisionCodeListenerBindFailed, "no listen addr", nil)
	failProvision(r, func() { notified = true })

	if !notified {
		t.Error("notify func not called")
	}
	if exitCode != provisionExitCodeForCode[provisionCodeListenerBindFailed] {
		t.Errorf("exit code = %d", exitCode)
	}
	out, err := readProvisionResult()
	if err != nil {
		t.Fatalf("result not persisted: %v", err)
	}
	if out.Code != string(provisionCodeListenerBindFailed) {
		t.Errorf("persisted code = %q", out.Code)
	}
}

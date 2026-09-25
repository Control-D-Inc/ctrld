package cli

import (
	"testing"
	"time"
)

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

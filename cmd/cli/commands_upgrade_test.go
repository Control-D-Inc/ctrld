package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kardianos/service"
)

// fakeService implements the parts of service.Service that rollback uses. Any other
// method panics, which keeps accidental dependencies visible.
type fakeService struct {
	service.Service

	stopErr    error
	stopCalls  int
	statuses   []service.Status // consumed one per Status() call; the last repeats
	statusErr  error
	onStopCall func()
}

func (f *fakeService) Stop() error {
	f.stopCalls++
	if f.onStopCall != nil {
		f.onStopCall()
	}
	return f.stopErr
}

func (f *fakeService) Status() (service.Status, error) {
	if f.statusErr != nil {
		return service.StatusUnknown, f.statusErr
	}
	if len(f.statuses) == 0 {
		return service.StatusStopped, nil
	}
	st := f.statuses[0]
	if len(f.statuses) > 1 {
		f.statuses = f.statuses[1:]
	}
	return st, nil
}

func TestStopServiceAndWait(t *testing.T) {
	tests := []struct {
		name    string
		svc     *fakeService
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "stops after a few polls",
			svc:     &fakeService{statuses: []service.Status{service.StatusRunning, service.StatusRunning, service.StatusStopped}},
			timeout: 5 * time.Second,
		},
		{
			name:    "already stopped",
			svc:     &fakeService{statuses: []service.Status{service.StatusStopped}},
			timeout: 5 * time.Second,
		},
		{
			// A stop request that errors is not fatal on its own: the process may be
			// exiting anyway, so the status poll decides.
			name:    "stop errors but service is stopped",
			svc:     &fakeService{stopErr: errors.New("already stopped"), statuses: []service.Status{service.StatusStopped}},
			timeout: 5 * time.Second,
		},
		{
			name:    "not installed",
			svc:     &fakeService{statusErr: service.ErrNotInstalled},
			timeout: 5 * time.Second,
		},
		{
			// The process never exits. Rollback must be told so, because modifying a
			// running executable is what produced "Access is denied".
			name:    "never stops",
			svc:     &fakeService{statuses: []service.Status{service.StatusRunning}},
			timeout: time.Millisecond,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := stopServiceAndWait(tc.svc, tc.timeout)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.svc.stopCalls != 1 {
				t.Errorf("Stop() called %d times, want 1", tc.svc.stopCalls)
			}
		})
	}
}

func TestRemoveBinaryWithRetry(t *testing.T) {
	t.Run("removes an existing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ctrld")
		if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := removeBinaryWithRetry(path, time.Second); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("file still exists after removal: %v", err)
		}
	})

	t.Run("missing file is not an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent")
		if err := removeBinaryWithRetry(path, time.Second); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("gives up and reports when the path cannot be removed", func(t *testing.T) {
		// A non-empty directory stands in for a locked executable: os.Remove keeps
		// failing, so the retry loop must surface the error rather than hang.
		dir := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "child"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := removeBinaryWithRetry(dir, time.Millisecond); err == nil {
			t.Fatal("expected an error for a path that cannot be removed")
		}
	})
}

func TestBinaryVersion(t *testing.T) {
	t.Run("reports the version", func(t *testing.T) {
		t.Setenv(envFakeVersionOutput, "ctrld version dev-94fbd3f")
		got, err := binaryVersion(os.Args[0])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "dev-94fbd3f" {
			t.Errorf("binaryVersion() = %q, want %q", got, "dev-94fbd3f")
		}
	})

	t.Run("rejects a binary that prints no version", func(t *testing.T) {
		// The incident's ctrld.exe_previous: the file exists and runs, but produces no
		// version output. Restoring it would have replaced a hung service with one
		// that cannot start at all.
		t.Setenv(envFakeVersionOutput, envFakeVersionSilent)
		if _, err := binaryVersion(os.Args[0]); err == nil {
			t.Fatal("expected an error for a binary with no version output")
		}
	})

	t.Run("rejects a missing binary", func(t *testing.T) {
		if _, err := binaryVersion(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("expected an error for a missing binary")
		}
	})
}

// stubBinaryVersion makes the version probe report ver for any path, so a rollback
// test does not have to stage a runnable executable.
//
// Staging one is not portable: oldBin is bin+"_previous", so a fixture named "ctrld"
// yields the extension-less "ctrld_previous", which Windows refuses to execute
// ("executable file not found in %PATH%"), and a symlink to the test binary needs a
// privilege Windows does not grant by default. The probe itself is covered against the
// real test binary in TestBinaryVersion; these tests are about rollback's ordering.
func stubBinaryVersion(t *testing.T, ver string, err error) {
	t.Helper()
	prev := binaryVersionFn
	binaryVersionFn = func(string) (string, error) { return ver, err }
	t.Cleanup(func() { binaryVersionFn = prev })
}

func TestRollbackToPreviousBinaryStopsBeforeTouchingTheBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ctrld")
	oldBin := bin + oldBinSuffix
	if err := os.WriteFile(bin, []byte("replacement"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldBin, []byte("previous"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubBinaryVersion(t, "dev-a75d669", nil)

	// The invariant: when stop runs, the replacement's executable is still untouched.
	// Reversing these two is exactly the "Access is denied" defect.
	var stopped bool
	var binExistedAtStop bool
	stop := func() error {
		stopped = true
		_, err := os.Stat(bin)
		binExistedAtStop = err == nil
		return nil
	}
	restarted := false
	restart := func() bool { restarted = true; return true }

	if err := rollbackToPreviousBinary(bin, oldBin, stop, restart); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stopped {
		t.Error("rollback did not stop the service")
	}
	if !binExistedAtStop {
		t.Error("the binary was modified before the service was stopped")
	}
	if !restarted {
		t.Error("rollback did not restart the service")
	}
	if _, err := os.Stat(oldBin); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("previous binary was not moved into place: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Errorf("restored binary is missing: %v", err)
	}
}

func TestRollbackToPreviousBinaryKeepsUnusablePrevious(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ctrld")
	oldBin := bin + oldBinSuffix
	if err := os.WriteFile(bin, []byte("replacement"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A previous binary that exists but does not report a version, as in the incident.
	if err := os.WriteFile(oldBin, []byte("not a working binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Stubbed rather than left to the real probe: that would fail here for the right
	// reason on unix (not an executable) but the wrong one on Windows (the fixture's
	// name has no extension), so the assertion would not be about usability at all.
	stubBinaryVersion(t, "", errors.New("unexpected --version output"))

	stopped := false
	restarted := false
	err := rollbackToPreviousBinary(bin, oldBin,
		func() error { stopped = true; return nil },
		func() bool { restarted = true; return true },
	)
	if err == nil {
		t.Fatal("expected an error when the previous binary is unusable")
	}
	if !stopped {
		t.Error("the service must still be stopped: a broken replacement holds enforcement")
	}
	if restarted {
		t.Error("must not restart the service with an unusable binary")
	}
	// Nothing was swapped, and the previous file is kept for inspection.
	if _, err := os.Stat(oldBin); err != nil {
		t.Errorf("unusable previous binary was not preserved: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Errorf("installed binary was removed despite having nothing to restore: %v", err)
	}
}

func TestRollbackToPreviousBinaryAbortsWhenStopFails(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ctrld")
	oldBin := bin + oldBinSuffix
	for _, p := range []string{bin, oldBin} {
		if err := os.WriteFile(p, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	stopErr := errors.New("service did not stop within 30s")
	err := rollbackToPreviousBinary(bin, oldBin,
		func() error { return stopErr },
		func() bool { t.Error("must not restart after a failed stop"); return false },
	)
	if !errors.Is(err, stopErr) {
		t.Fatalf("error = %v, want %v", err, stopErr)
	}
	// The executable of a process that may still be running must be left alone.
	if _, err := os.Stat(bin); err != nil {
		t.Errorf("binary was modified even though the stop failed: %v", err)
	}
}

package cli

import (
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// startControlSocket serves handler on a unix socket and returns its path.
func startControlSocket(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	// Keep the path short: unix socket paths have a low length limit.
	dir, err := os.MkdirTemp("", "ctrldsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sockPath := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(startedPath, handler)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sockPath
}

func TestServiceReadyAt(t *testing.T) {
	t.Run("ready when the control server reports started", func(t *testing.T) {
		sock := startControlSocket(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		ready, err := serviceReadyAt(sock, time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ready {
			t.Error("ready = false, want true")
		}
	})

	t.Run("not ready when startup has not finished", func(t *testing.T) {
		// What /started returns when the onStarted hooks have not completed.
		sock := startControlSocket(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusRequestTimeout)
		})
		ready, err := serviceReadyAt(sock, time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ready {
			t.Error("ready = true for a control server that has not finished startup")
		}
	})

	t.Run("not ready when there is no control socket", func(t *testing.T) {
		// The incident: the process was alive but had never created the socket, so
		// every control request was refused.
		ready, err := serviceReadyAt(filepath.Join(t.TempDir(), "absent.sock"), time.Second)
		if ready {
			t.Error("ready = true with no control socket")
		}
		if err == nil {
			t.Error("expected an error when the control socket does not exist")
		}
	})

	t.Run("not ready when the probe times out", func(t *testing.T) {
		sock := startControlSocket(t, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		})
		ready, err := serviceReadyAt(sock, 50*time.Millisecond)
		if ready {
			t.Error("ready = true for a probe that timed out")
		}
		if err == nil {
			t.Error("expected an error when the probe times out")
		}
	})
}

func TestClassifyReadiness(t *testing.T) {
	tests := []struct {
		name       string
		ready      bool
		err        error
		verifiable bool
		wantCode   int
	}{
		{
			name:       "ready",
			ready:      true,
			verifiable: true,
			wantCode:   statusExitRunning,
		},
		{
			// The service manager says running, the process is not serving. This
			// must not report success.
			name:       "running but never finished startup",
			err:        errors.New("connect: connection refused"),
			verifiable: true,
			wantCode:   statusExitNotReady,
		},
		{
			// A caller without privilege cannot probe; that is not evidence of a
			// broken service, so it must not be reported as one.
			name:       "probe not permitted",
			err:        fs.ErrPermission,
			verifiable: true,
			wantCode:   statusExitRunning,
		},
		{
			name:       "wrapped permission error",
			err:        &net.OpError{Op: "dial", Err: fs.ErrPermission},
			verifiable: true,
			wantCode:   statusExitRunning,
		},
		{
			// The P2: an unprivileged caller on unix resolves a socket path the
			// daemon never used, so the probe fails with ENOENT rather than a
			// permission error. That says nothing about the service and must not be
			// reported as unhealthy - a monitoring check acting on exit 3 would
			// restart a healthy daemon.
			name:       "missing socket at an unverifiable path",
			err:        &net.OpError{Op: "dial", Err: os.ErrNotExist},
			verifiable: false,
			wantCode:   statusExitRunning,
		},
		{
			name:       "connection refused at an unverifiable path",
			err:        errors.New("connect: connection refused"),
			verifiable: false,
			wantCode:   statusExitRunning,
		},
		{
			// A probe that actually reached the socket is conclusive whoever ran it.
			name:       "successful probe is trusted even when unverifiable",
			ready:      true,
			verifiable: false,
			wantCode:   statusExitRunning,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyReadiness(tc.ready, tc.err, tc.verifiable)
			if got.exitCode != tc.wantCode {
				t.Errorf("exitCode = %d, want %d", got.exitCode, tc.wantCode)
			}
			if len(got.messages) == 0 {
				t.Error("no message to report")
			}
		})
	}
}

// TestReadinessVerifiableMatchesSocketVisibility is the closure test for the P2: the
// not-ready verdict must only be reachable when this process resolves the same socket
// directory the daemon uses.
//
// On unix that is the privileged user's path, so an unprivileged run - which is how
// "ctrld status" is normally invoked, since only darwin has an elevation PreRun and the
// root-level alias has none - must not be able to reach exit 3.
func TestReadinessVerifiableMatchesSocketVisibility(t *testing.T) {
	verifiable := readinessVerifiable()

	if runtime.GOOS == "windows" {
		if !verifiable {
			t.Error("on Windows every caller resolves the install directory, so the probe is always verifiable")
		}
		return
	}

	elevated, err := hasElevatedPrivilege()
	if err != nil {
		t.Skipf("cannot determine privilege: %v", err)
	}
	if verifiable != elevated {
		t.Errorf("readinessVerifiable() = %v, want %v (elevated)", verifiable, elevated)
	}

	if !elevated {
		// The shape the review asked to assert: unprivileged, healthy daemon, and a
		// probe that cannot see its socket must still report running.
		dir, err := socketDir()
		if err != nil {
			t.Fatalf("socketDir(): %v", err)
		}
		if dir == "/var/run" {
			t.Skip("unprivileged but /var/run is writable, so the probe path does match")
		}
		r := classifyReadiness(false, &net.OpError{Op: "dial", Err: os.ErrNotExist}, verifiable)
		if r.exitCode == statusExitNotReady {
			t.Errorf("unprivileged status probing %q reported not-ready (exit %d) for a healthy service", dir, r.exitCode)
		}
	}
}

// Every status must map to its own exit code: a caller that cannot tell a hung
// service from a healthy or a stopped one is back to the incident's diagnostics.
//
// The literal values are the contract. statusCmdLong documents them and monitoring
// scripts key off them, so asserting the constants against each other would let a
// renumbering keep the suite green while silently breaking every caller.
func TestStatusExitCodesAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"running", statusExitRunning, 0},
		{"stopped", statusExitStopped, 1},
		{"unknown", statusExitUnknown, 2},
		{"not ready", statusExitNotReady, 3},
	} {
		if tc.got != tc.want {
			t.Errorf("%s exit code = %d, want %d: statusCmdLong and monitoring scripts document this value", tc.name, tc.got, tc.want)
		}
	}

	codes := map[int]string{
		statusExitRunning:  "running",
		statusExitStopped:  "stopped",
		statusExitUnknown:  "unknown",
		statusExitNotReady: "not ready",
	}
	if len(codes) != 4 {
		t.Errorf("status exit codes collide, only %d distinct: %v", len(codes), codes)
	}
}

// TestReadinessProbeStatusHandling covers what each control-server answer means.
//
// http.Client.Post returns (resp, nil) for any status code, so a daemon without the
// /started route answers 404 and the probe must report "cannot confirm" rather than "not
// started". That state is reached in normal operation - after an upgrade replaces the
// binary but before the service restarts, and throughout a mixed-version rollout - and
// reporting exit 3 there tells monitoring to restart a healthy service.
func TestReadinessProbeStatusHandling(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		wantReady    bool
		wantReported bool // whether the answer carries a readiness verdict
		wantExitCode int
	}{
		{"started", http.StatusOK, true, true, statusExitRunning},
		{"still starting", http.StatusRequestTimeout, false, true, statusExitNotReady},
		{"no readiness route", http.StatusNotFound, false, false, statusExitRunning},
		{"control server error", http.StatusInternalServerError, false, false, statusExitRunning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.status
			sock := startControlSocket(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})

			ready, err := serviceReadyAt(sock, time.Second)
			if ready != tc.wantReady {
				t.Errorf("ready = %v, want %v", ready, tc.wantReady)
			}
			if reported := !errors.Is(err, errReadinessNotReported); reported != tc.wantReported {
				t.Errorf("readiness reported = %v, want %v (err: %v)", reported, tc.wantReported, err)
			}
			if got := classifyReadiness(ready, err, true).exitCode; got != tc.wantExitCode {
				t.Errorf("exit code = %d, want %d", got, tc.wantExitCode)
			}
		})
	}
}

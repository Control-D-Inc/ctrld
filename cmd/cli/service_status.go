package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"runtime"
	"time"
)

// Exit codes reported by "ctrld status".
const (
	statusExitRunning = 0
	statusExitStopped = 1
	statusExitUnknown = 2
	// statusExitNotReady means the service manager considers the service running,
	// but the process has not finished starting up, so it is not serving DNS or
	// applying policy. This is a distinct code because it needs a distinct response:
	// the process exists, so restarting the service is what recovers it, while a
	// stopped service needs starting and an unknown state needs investigation.
	statusExitNotReady = 3
)

// serviceReadinessTimeout bounds the control-socket probe. Status must answer
// quickly, and a service that cannot respond within this window is not usefully
// "running" from a caller's point of view either way.
const serviceReadinessTimeout = 3 * time.Second

// statusCmdLong documents what the reported states mean, including that a service the
// OS calls running is not necessarily serving.
const statusCmdLong = `Show status of the ctrld service.

Reports both what the OS service manager thinks and whether ctrld has finished
starting up, since a service can be registered as running while its process is
still in startup and serving nothing.

Exit codes:
  0  running and serving, or running with startup not verified
  1  stopped
  2  status unknown
  3  registered as running, but startup has not completed

Verifying startup requires reaching ctrld's control socket. On Linux, BSD and macOS
that socket lives in a directory only the privileged user resolves, so an
unprivileged "ctrld status" reports the service manager's view and says startup was
not verified rather than claiming the service is unhealthy. Exit 3 is only reported
when the check could actually be made.`

// readiness is what "ctrld status" reports for a service the service manager
// considers running.
type readiness struct {
	messages []string
	exitCode int
}

// readinessVerifiable reports whether a failed control-socket probe can be trusted to
// mean "the service has not finished starting up".
//
// It can only mean that if this process resolves the same socket path the daemon
// created, and socketDir() is caller-relative on unix: it returns the system directory
// only when that is writable, and the caller's home directory otherwise. So a
// root-owned daemon listens on /var/run/ctrld_control.sock while an unprivileged
// "ctrld status" looks under $HOME, finds nothing, and gets ENOENT - which means "wrong
// path", not "not ready". Reporting exit 3 there would tell a monitoring check to
// restart a perfectly healthy daemon.
//
// On Windows and mobile socketDir() is the install/home directory for every caller, so
// the probe is comparable - which matters because Windows is where the hung-start this
// exit code exists for was seen. On Windows that only holds while this binary is the
// installed one: a copy run from elsewhere resolves a different socket directory, so its
// failed probe would say nothing about the service. installedServiceDirMatches() checks
// that, and answers true when it cannot tell, preserving the previous behaviour.
func readinessVerifiable() bool {
	if isMobile() {
		return true
	}
	if runtime.GOOS == "windows" {
		return installedServiceDirMatches()
	}
	elevated, err := hasElevatedPrivilege()
	return err == nil && elevated
}

// classifyReadiness turns a control-socket probe result into the report for a service
// the service manager calls running.
//
// verifiable comes from readinessVerifiable: when it is false a failed probe says
// nothing about the service, so the report falls back to the service manager's view.
// A *successful* probe is still conclusive either way - reaching the socket at all is
// positive evidence, whoever the caller is.
func classifyReadiness(ready bool, err error, verifiable bool) readiness {
	switch {
	case ready:
		return readiness{
			messages: []string{"Service is running"},
			exitCode: statusExitRunning,
		}
	case !verifiable:
		return readiness{
			messages: []string{"Service is running (startup not verified: re-run with elevated privileges to check readiness)"},
			exitCode: statusExitRunning,
		}
	case errors.Is(err, errReadinessNotReported):
		// The service answered, just not with a verdict - an older daemon without the
		// /started route. It is alive and reachable, so the service manager's view is
		// the best available answer.
		return readiness{
			messages: []string{"Service is running (startup not verified: this ctrld build does not report readiness)"},
			exitCode: statusExitRunning,
		}
	case errors.Is(err, fs.ErrPermission):
		// Without access to the control socket there is nothing to report beyond the
		// service manager's view. Do not call a service unhealthy because the caller
		// lacks privilege.
		return readiness{
			messages: []string{"Service is running (startup not verified: control socket requires elevated privileges)"},
			exitCode: statusExitRunning,
		}
	default:
		return readiness{
			messages: []string{
				"Service is registered as running, but has not completed startup: it is not serving DNS",
				"Check the ctrld log for why startup did not finish, then restart the service",
			},
			exitCode: statusExitNotReady,
		}
	}
}

// serviceReady reports whether a running ctrld has finished starting up, by asking
// its control server. The control server answers /started only once the onStarted
// hooks have completed, which is after the DNS listeners are up, so a successful
// probe means the process is actually serving rather than merely alive.
//
// An error means "could not confirm readiness" and is returned for the caller to
// classify: a refused connection or missing socket is a process that never got that
// far, while a permission error says nothing about the service's health.
func serviceReady() (bool, error) {
	dir, err := socketDir()
	if err != nil {
		return false, err
	}
	return serviceReadyAt(filepath.Join(dir, ControlSocketName()), serviceReadinessTimeout)
}

// errReadinessNotReported marks a control server that answered without a readiness
// verdict.
//
// http.Client.Post returns (resp, nil) for any status, so a daemon with no /started
// route answers 404 and an internal failure answers 5xx - neither says the service has
// not started. Reporting "not ready" there tells a monitoring check to restart a healthy
// service, and it happens in normal operation: after an upgrade replaces the binary on
// disk but before the service restarts, and throughout a mixed-version rollout.
var errReadinessNotReported = errors.New("control server did not report readiness")

// serviceReadyAt is serviceReady against an explicit socket path and timeout.
func serviceReadyAt(sockPath string, timeout time.Duration) (bool, error) {
	cc := newControlClient(sockPath)
	cc.c.Timeout = timeout
	resp, err := cc.post(startedPath, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusRequestTimeout:
		// The daemon's own verdict: its onStarted hooks have not completed. This is the
		// hung start statusExitNotReady exists for.
		return false, nil
	default:
		return false, fmt.Errorf("%w: HTTP %d", errReadinessNotReported, resp.StatusCode)
	}
}

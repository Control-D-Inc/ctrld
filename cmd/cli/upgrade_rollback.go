package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kardianos/service"
)

const (
	// upgradeStopTimeout bounds how long rollback waits for the replacement process to
	// exit, and for Windows to release the lock on its image afterwards.
	upgradeStopTimeout = 30 * time.Second
	// upgradeStopPollInterval is how often the service status is re-checked while
	// waiting for the process to exit.
	upgradeStopPollInterval = 500 * time.Millisecond
	// binaryVersionTimeout bounds the "--version" probe, so a binary that hangs on
	// startup cannot hang the upgrade.
	binaryVersionTimeout = 10 * time.Second
)

// rollbackToPreviousBinary restores oldBin over bin after the replacement failed to
// become ready, and restarts the service on the restored binary.
//
// stop must leave the replacement's process gone, because every step here modifies
// the executable that process is running from. It is called first for that reason:
// readiness failing does not mean the process exited - the service manager can report
// a started service whose process never became operational. Windows holds an
// exclusive lock on a running executable's image, so the previous code's
// os.Remove(bin) failed there with "Access is denied", and because that was fatal the
// restore never ran: the broken binary stayed installed with the previous one
// stranded at its _previous name.
//
// Stopping first also puts the host back in a known state, since a stopped ctrld
// holds no DNS or intercept enforcement.
func rollbackToPreviousBinary(bin, oldBin string, stop func() error, restart func() bool) error {
	if err := stop(); err != nil {
		mainLog.Load().Error().Err(err).Msg("Could not confirm the service stopped; not modifying its binary")
		return err
	}

	// Only restore a previous binary that actually runs: a _previous file that exists
	// but reports no version would replace a service that starts and hangs with one
	// that cannot start at all.
	//
	// The probe is retried for the same reason removeBinaryWithRetry is: on Windows a
	// single exec can fail transiently while antivirus scans the file or the disk is
	// busy, and treating that as "no usable previous binary" leaves the host stopped
	// with the broken binary installed - an end state worse than restoring a binary
	// that turns out to be bad, which the restart check below catches.
	//
	// Running "--version" proves the file executes. It is not an authenticity check:
	// nothing here compares a signature or checksum before a file becomes the installed
	// service binary. That is acceptable only because the install directory is writable
	// by administrators alone, which is this command's standing assumption.
	prevVer, err := binaryVersionWithRetry(oldBin, upgradeStopTimeout)
	if err != nil {
		mainLog.Load().Error().Err(err).Msgf("Previous binary at %s is not usable, keeping it for inspection", oldBin)
		mainLog.Load().Notice().Msgf("Service is stopped and %s is still the installed binary", bin)
		return fmt.Errorf("upgrade failed and no usable previous binary to restore: %w", err)
	}

	mainLog.Load().Warn().Msgf("Restoring previous binary: %s (%s)", oldBin, prevVer)
	if err := removeBinaryWithRetry(bin, upgradeStopTimeout); err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to remove new binary")
		mainLog.Load().Notice().Msg("Service is stopped")
		return err
	}
	if err := os.Rename(oldBin, bin); err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to restore old binary")
		mainLog.Load().Notice().Msgf("Service is stopped and %s is missing; reinstall ctrld to recover", bin)
		return err
	}
	if restart() {
		mainLog.Load().Notice().Msgf("Restored previous binary successfully - %s", prevVer)
		return nil
	}

	mainLog.Load().Error().Msg("Restored the previous binary but it did not become ready either")
	return errors.New("upgrade failed and the restored binary did not become ready")
}

// stopServiceAndWait stops the service and waits until the service manager reports
// it stopped. Rollback needs the process gone, not merely asked to stop: a stop
// request returns before the process exits, and on Windows the executable stays
// locked until it does.
func stopServiceAndWait(s service.Service, timeout time.Duration) error {
	if err := s.Stop(); err != nil {
		// Not fatal: the service may already be stopped, or stopping may fail while
		// the process is exiting anyway. The status poll below decides.
		mainLog.Load().Debug().Err(err).Msg("Stop request failed, waiting for the process to exit anyway")
	}
	deadline := time.Now().Add(timeout)
	statusReadable := false
	var lastErr error
	for {
		status, err := s.Status()
		switch {
		case errors.Is(err, service.ErrNotInstalled):
			return nil
		case err == nil:
			statusReadable = true
			if status == service.StatusStopped {
				return nil
			}
		default:
			lastErr = err
		}
		if !time.Now().Before(deadline) {
			if !statusReadable {
				// The status was never readable, so "did not stop" was never observed -
				// only "could not be observed". Refusing to continue here would leave the
				// broken binary installed with the service stopped, which is the outcome
				// rollback exists to avoid. Let the caller proceed: the remove is retried
				// while the image is locked, and the restart check still has to pass
				// before this reports success.
				mainLog.Load().Warn().Err(lastErr).Msgf("Could not read service status within %s; continuing with rollback", timeout)
				return nil
			}
			return fmt.Errorf("service did not stop within %s", timeout)
		}
		time.Sleep(upgradeStopPollInterval)
	}
}

// binaryVersionWithRetry probes a binary's version, retrying transient exec failures
// until timeout. Only the last error is reported: the earlier attempts are noise once a
// retry has been made.
func binaryVersionWithRetry(path string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		version, err := binaryVersionFn(path)
		if err == nil {
			return version, nil
		}
		if !time.Now().Before(deadline) {
			return "", err
		}
		mainLog.Load().Debug().Err(err).Msgf("Version probe of %s failed, retrying", path)
		time.Sleep(upgradeStopPollInterval)
	}
}

// removeBinaryWithRetry removes path, retrying while it is still locked. Windows
// releases the lock on an executable's image asynchronously after its process exits,
// so a remove issued immediately after the service reports stopped can still fail
// with "Access is denied".
func removeBinaryWithRetry(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("could not remove %s within %s: %w", path, timeout, err)
		}
		time.Sleep(upgradeStopPollInterval)
	}
}

// binaryVersionFn is indirected so rollback can be tested without staging a runnable
// executable per platform. The probe itself is covered directly against the test
// binary; see TestBinaryVersion.
var binaryVersionFn = binaryVersion

// binaryVersion runs path with "--version" and returns the version it reports. It
// answers "can this binary actually run on this host", which is what rollback needs
// to know before making a file the installed ctrld.
//
// On Windows path is ctrld.exe_previous, whose extension is not in PATHEXT. That
// resolves because os/exec only falls back to appending PATHEXT entries when the path
// has no extension at all (lp_windows.go findExecutable): with one present and the
// file on disk, it is used as-is. A suffix that left no extension - renaming
// oldBinSuffix such that the result is "ctrld_previous" - would break this probe with
// "executable file not found in %PATH%", and rollback would then refuse to restore a
// perfectly good binary.
func binaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), binaryVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("running %s --version: %w", path, err)
	}
	ver, found := strings.CutPrefix(strings.TrimSpace(string(out)), "ctrld version ")
	if !found {
		return "", fmt.Errorf("unexpected --version output from %s: %q", path, strings.TrimSpace(string(out)))
	}
	return ver, nil
}

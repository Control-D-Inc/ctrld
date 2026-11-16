package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
)

const (
	upgradeChannelDev  = "dev"
	upgradeChannelProd = "prod"
)

// UpgradeCommand handles upgrade-related operations
type UpgradeCommand struct {
	// targetVersion and targetBranch are the --version and --branch flags.
	targetVersion string
	targetBranch  string
}

// NewUpgradeCommand creates a new upgrade command handler
func NewUpgradeCommand() (*UpgradeCommand, error) {
	return &UpgradeCommand{}, nil
}

// defaultUpgradeChannel is the channel "ctrld-client upgrade" uses when none
// is given: prod for a release build, dev otherwise.
func defaultUpgradeChannel() string {
	if isStableVersion(curVersion()) {
		return upgradeChannelProd
	}
	return upgradeChannelDev
}

// Upgrade performs the upgrade operation
func (uc *UpgradeCommand) Upgrade(cmd *cobra.Command, args []string) error {
	req, err := newUpgradeRequest(args, uc.targetVersion, uc.targetBranch, defaultUpgradeChannel(), curVersion())
	if err != nil {
		mainLog.Load().Fatal().Msg(capitalize(err.Error()))
	}
	mainLog.Load().Notice().Msgf("Upgrading ctrld %s to the %s", curVersion(), req.describe())
	return runUpgrade("upgrade", req)
}

// Rollback performs the rollback operation: an upgrade to an older build.
func (uc *UpgradeCommand) Rollback(cmd *cobra.Command, args []string) error {
	req, err := newRollbackRequest(curVersion(), uc.targetVersion, uc.targetBranch)
	if err != nil {
		mainLog.Load().Fatal().Msg(capitalize(err.Error()))
	}
	mainLog.Load().Notice().Msgf("Rolling ctrld back from %s to the %s", curVersion(), req.describe())
	return runUpgrade("rollback", req)
}

// runUpgrade downloads the binary req asks for and installs it. action names
// the change in log messages.
func runUpgrade(action string, req upgradeRequest) error {
	t, err := newBinarySwitch()
	if err != nil {
		mainLog.Load().Error().Msg(err.Error())
		return nil
	}

	dlUrl := req.downloadUrl(upgradeBaseUrls[req.channel])
	mainLog.Load().Debug().Msgf("Downloading binary: %s", dlUrl)

	resp, err := getWithRetry(dlUrl, downloadServerIp)
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("Failed to download binary")
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound && req.version != "":
		mainLog.Load().Fatal().Msgf("Version %s is not available for download", req.version)
	case resp.StatusCode == http.StatusNotFound && req.branch != "":
		mainLog.Load().Fatal().Msgf("No build of branch %s is available for download", req.branch)
	case resp.StatusCode == http.StatusBadRequest && (req.version != "" || req.branch != ""):
		mainLog.Load().Fatal().Msgf("Download server rejected the request for the %s", req.describe())
	case resp.StatusCode != http.StatusOK:
		mainLog.Load().Fatal().Msgf("Could not download binary: %s", http.StatusText(resp.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBinarySize+1))
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("Failed to download binary")
	}
	if len(data) > maxDownloadBinarySize {
		mainLog.Load().Fatal().Msgf("Downloaded binary is larger than %d bytes", maxDownloadBinarySize)
	}
	if req.version != "" {
		if _, err := verifyDownloadedVersion(data, t.bin, req.version); err != nil {
			mainLog.Load().Fatal().Err(err).Msg("Downloaded binary is not the requested version, nothing was changed")
		}
	}
	warnVersionTargetOverride(req, runningVersionTarget)
	return t.install(action, data)
}

// binarySwitch replaces the installed ctrld binary and restarts the service
// on the new one, restoring the replaced binary from oldBin if the new one
// does not become ready.
type binarySwitch struct {
	bin, oldBin  string
	p            *prog
	s            service.Service
	svcInstalled bool
}

// newBinarySwitch prepares to replace the running ctrld binary.
func newBinarySwitch() (*binarySwitch, error) {
	bin, err := os.Executable()
	if err != nil {
		mainLog.Load().Fatal().Err(err).Msg("Failed to get current ctrld binary path")
	}

	readConfig(false)
	v.Unmarshal(&cfg)
	svcCmd := NewServiceCommand()
	s, p, err := svcCmd.initializeServiceManager()
	if err != nil {
		return nil, err
	}

	if iface == "" {
		iface = autoIface
	}
	p.preRun()
	if ir := runningIface(s); ir != nil {
		p.setRunningIfaceFromService(ir)
	}

	svcInstalled := true
	if _, err := s.Status(); errors.Is(err, service.ErrNotInstalled) {
		svcInstalled = false
	}
	return &binarySwitch{bin: bin, oldBin: bin + oldBinSuffix, p: p, s: s, svcInstalled: svcInstalled}, nil
}

// install makes data the installed binary and restarts the service on it.
// action names the change in log messages.
func (t *binarySwitch) install(action string, data []byte) error {
	fromVer := curVersion()
	mainLog.Load().Debug().Msg("Updating current binary")
	if err := selfupdate.Apply(bytes.NewReader(data), selfupdate.Options{TargetPath: t.bin, OldSavePath: t.oldBin}); err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			mainLog.Load().Error().Err(rerr).Msg("Could not rollback old binary")
		}
		mainLog.Load().Fatal().Err(err).Msg("Failed to update current binary")
	}

	s, p := t.s, t.p
	doRestart := func() bool {
		if !t.svcInstalled {
			return true
		}
		tasks := []task{
			{s.Stop, true, "Stop"},
			{func() error {
				// Restore static DNS settings or DHCP, leaving adapter DNS
				// ctrld did not set alone when the service intercepts.
				p.resetDNSAfterServiceStop()
				return nil
			}, false, "Cleanup"},
			{func() error {
				time.Sleep(time.Second * 1)
				return nil
			}, false, "Waiting for service to stop"},
		}
		doTasks(tasks)

		tasks = []task{
			{s.Start, true, "Start"},
		}
		if doTasks(tasks) {
			if dir, err := socketDir(); err == nil {
				// Only a ready service counts: a build that starts but
				// never becomes ready must be rolled back.
				if cc := newReadySocketControlClient(context.TODO(), s, dir); cc != nil {
					_, _ = cc.post(ifacePath, nil)
					return true
				}
			}
		}
		return false
	}

	if t.svcInstalled {
		mainLog.Load().Debug().Msg("Restarting ctrld service using new binary")
	}

	if doRestart() {
		_ = os.Remove(t.oldBin)
		_ = os.Chmod(t.bin, 0755)
		ver, err := binaryVersionFn(t.bin)
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("Failed to get new binary version")
			ver = "unknown version"
		}
		logVersionChange(action, fromVer, ver)
		return nil
	}

	stop := func() error {
		if !t.svcInstalled {
			return nil
		}
		if err := stopServiceAndWait(s, upgradeStopTimeout); err != nil {
			return err
		}
		// Mirror the Cleanup task in doRestart: leave DNS settings as the OS had them,
		// not as a half-started ctrld left them.
		p.resetDNSAfterServiceStop()
		return nil
	}
	return rollbackToPreviousBinary(t.bin, t.oldBin, stop, doRestart)
}

// rollbackToPreviousBinary restores oldBin over bin after the replacement failed to
// become ready, and restarts the service on the restored binary.
//
// stop must leave the replacement's process gone, because every step here modifies
// the executable that process is running from. It is called first for that reason:
// readiness failing does not mean the process exited - the service manager can report
// a started service whose process never became operational, which is what the Windows
// Firewall Mode incident produced. Windows holds an exclusive lock on a running
// executable's image, so the previous code's os.Remove(bin) failed with "Access is
// denied", and because that was fatal the restore never ran: the broken binary stayed
// installed with the previous one stranded at its _previous name.
//
// Stopping first also puts the host back in a known state. A stopped ctrld holds no
// WFP or NRPT enforcement, so a replacement that was blocking traffic stops blocking
// it here instead of at the next reboot.
func rollbackToPreviousBinary(bin, oldBin string, stop func() error, restart func() bool) error {
	if err := stop(); err != nil {
		mainLog.Load().Error().Err(err).Msg("Could not confirm the service stopped; not modifying its binary")
		return err
	}

	// Only restore a previous binary that actually runs. During the incident the
	// _previous file existed but produced no version output; renaming that over the
	// current binary would have replaced a service that starts but hangs with one that
	// cannot start at all.
	//
	// The probe is retried for the same reason removeBinaryWithRetry is: on Windows a
	// single exec can fail transiently while antivirus scans the file or the disk is
	// busy, and treating that as "no usable previous binary" leaves the host stopped
	// with the broken binary installed and no enforcement - an end state worse than
	// restoring a binary that turns out to be bad, which the restart check below
	// catches.
	//
	// Running "--version" proves the file executes. It is not an authenticity check:
	// nothing here compares a signature or checksum before a file becomes the installed
	// service binary. That is acceptable only because the install directory is writable
	// by administrators alone, which is this command's standing assumption.
	prevVer, err := binaryVersionWithRetry(oldBin, upgradeStopTimeout)
	if err != nil {
		mainLog.Load().Error().Err(err).Msgf("Previous binary at %s is not usable, keeping it for inspection", oldBin)
		mainLog.Load().Notice().Msgf("Service is stopped and %s is still the installed binary - no ctrld enforcement is active", bin)
		return fmt.Errorf("upgrade failed and no usable previous binary to restore: %w", err)
	}

	mainLog.Load().Warn().Msgf("Restoring previous binary: %s (%s)", oldBin, prevVer)
	if err := removeBinaryWithRetry(bin, upgradeStopTimeout); err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to remove new binary")
		mainLog.Load().Notice().Msg("Service is stopped - no ctrld enforcement is active")
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
				// broken binary installed with the service stopped and no enforcement,
				// which is the outcome rollback exists to avoid. Let the caller proceed:
				// the remove is retried while the image is locked, and the restart check
				// still has to pass before this reports success.
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
// On Windows path is ctrld-client.exe_previous, whose extension is not in PATHEXT. That
// resolves because os/exec only falls back to appending PATHEXT entries when the path
// has no extension at all (lp_windows.go findExecutable): with one present and the
// file on disk, it is used as-is. A suffix that left no extension - renaming
// oldBinSuffix such that the result is "ctrld-client_previous" - would break this probe with
// "executable file not found in %PATH%", and rollback would then refuse to restore a
// perfectly good binary.
func binaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), binaryVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("running %s --version: %w", path, err)
	}
	ver, ok := parseVersionOutput(string(out))
	if !ok {
		return "", fmt.Errorf("unexpected --version output from %s: %q", path, strings.TrimSpace(string(out)))
	}
	return ver, nil
}

// parseVersionOutput extracts the version from a binary's "--version" output.
//
// The expected prefix is built from cliName, which is also what the root command
// is named, because Cobra renders "--version" as "<name> version <version>" from
// that same name. Spelling the prefix out here instead would make a rename of the
// client silently break this parser - and with it rollback, which refuses to
// restore a previous binary whose version it cannot read. That failure mode is
// the worst one this code has: the service is already stopped, so a wrongly
// rejected previous binary leaves the host with no ctrld enforcement at all.
func parseVersionOutput(out string) (string, bool) {
	// Not CutPrefix's own return: on a miss it hands back the whole input, which a
	// caller that forgot to check the bool would store as if it were a version.
	ver, ok := strings.CutPrefix(strings.TrimSpace(out), cliName+" version ")
	if !ok {
		return "", false
	}
	return ver, true
}

// InitUpgradeCmd creates the upgrade command with proper logic
func InitUpgradeCmd(rootCmd *cobra.Command) *cobra.Command {
	uc, _ := NewUpgradeCommand()
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrading ctrld to latest version",
		Long: `Upgrading ctrld to latest version.

Use --version to install a specific release from the prod channel, for
example to go back to an earlier release, or --branch to install the latest
build of a branch from the dev channel.`,
		Example: `  ctrld-client upgrade
  ctrld-client upgrade prod --version v1.5.7
  ctrld-client upgrade dev --branch master`,
		ValidArgs: []string{upgradeChannelDev, upgradeChannelProd},
		Args:      cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return uc.Upgrade(cmd, args)
		},
	}
	upgradeCmd.Flags().StringVarP(&uc.targetVersion, "version", "", "", "Release version to install, for example v1.2.3 (prod channel)")
	upgradeCmd.Flags().StringVarP(&uc.targetBranch, "branch", "", "", "Branch whose latest build to install (dev channel)")

	rootCmd.AddCommand(upgradeCmd)

	return upgradeCmd
}

// InitRollbackCmd creates the rollback command, which installs an older build
// through the same download, version check and restart as the upgrade command.
func InitRollbackCmd(rootCmd *cobra.Command) *cobra.Command {
	uc, _ := NewUpgradeCommand()
	rollbackCmd := &cobra.Command{
		Use:   "rollback",
		Short: "Roll ctrld back to the previous release",
		Long: `Roll ctrld back to the previous release.

Rollback is "ctrld-client upgrade prod --version" with an older release.
Without --version it installs the release before the installed one: from
v1.2.3 it installs v1.2.2. The release before a v1.2.0 is not known, and
development builds have no release version, so those need --version.

Use --branch to install the latest build of a branch from the dev channel
instead, like "ctrld-client upgrade dev --branch". Configuration and identity
are not changed.

On a device managed by Control D, a dashboard version target above the
installed release makes ctrld upgrade again at the next config refresh, so
clear or lower the target in the dashboard first.`,
		Example: `  ctrld-client rollback
  ctrld-client rollback --version v1.5.7
  ctrld-client rollback --branch master`,
		Args: cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			checkHasElevatedPrivilege()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return uc.Rollback(cmd, args)
		},
	}
	rollbackCmd.Flags().StringVarP(&uc.targetVersion, "version", "", "", "Release version to roll back to, for example v1.2.3 (default: the previous release)")
	rollbackCmd.Flags().StringVarP(&uc.targetBranch, "branch", "", "", "Branch whose latest build to roll back to (dev channel)")

	rootCmd.AddCommand(rollbackCmd)

	return rollbackCmd
}

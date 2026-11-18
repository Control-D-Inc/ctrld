package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/Control-D-Inc/ctrld"
)

const (
	// downloadBinSuffix names the file a downloaded binary is staged in while
	// its version is checked. It is appended after the full name
	// (ctrld-client.exe_download on Windows), so the name keeps an extension and
	// os/exec runs it as-is (see binaryVersion).
	downloadBinSuffix = "_download"

	// downloadProbeTimeout bounds the retries of the staged binary's version
	// probe. It is shorter than upgradeStopTimeout: it only needs to outlast an
	// antivirus scan of the new file, and a binary that cannot run on this
	// host fails the same way on every try.
	downloadProbeTimeout = 5 * time.Second

	// maxDownloadBinarySize bounds how much of a download is read into memory.
	maxDownloadBinarySize = 256 << 20
)

// upgradeBaseUrls maps each upgrade channel to its download server.
var upgradeBaseUrls = map[string]string{
	upgradeChannelDev:  "https://dl.controld.dev",
	upgradeChannelProd: "https://dl.controld.com",
}

var (
	// The download proxies reject values outside these patterns, so ctrld
	// rejects them first with a clearer message.
	upgradeVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	upgradeBranchPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// upgradeRequest is what "ctrld-client upgrade" was asked to install.
type upgradeRequest struct {
	channel string // upgradeChannelProd or upgradeChannelDev
	version string // release version with a leading "v", or empty for the latest
	branch  string // branch name, or empty for the default branch
}

// errVersionWithBranch is returned when both --version and --branch are given.
var errVersionWithBranch = errors.New(`"--version" and "--branch" cannot be used together`)

// newUpgradeRequest validates the upgrade arguments and flags. A version is
// a release, which only the prod channel serves, and a branch is a dev build,
// which only the dev channel serves. Each flag picks its channel when none is
// given, and is refused with the other channel.
func newUpgradeRequest(args []string, version, branch, defaultChannel, currentVersion string) (upgradeRequest, error) {
	req := upgradeRequest{channel: defaultChannel}
	if len(args) > 0 {
		switch args[0] {
		case upgradeChannelProd, upgradeChannelDev:
			req.channel = args[0]
		default:
			return req, fmt.Errorf("upgrade argument must be either %q or %q", upgradeChannelProd, upgradeChannelDev)
		}
	}
	switch {
	case version != "" && branch != "":
		return req, errVersionWithBranch
	case version != "":
		if len(args) > 0 && req.channel != upgradeChannelProd {
			return req, errors.New(`"--version" can only be used with "ctrld-client upgrade prod"`)
		}
		v, err := validateUpgradeVersion(version, currentVersion)
		if err != nil {
			return req, err
		}
		req.channel, req.version = upgradeChannelProd, v
	case branch != "":
		if len(args) > 0 && req.channel != upgradeChannelDev {
			return req, errors.New(`"--branch" can only be used with "ctrld-client upgrade dev"`)
		}
		if err := validateUpgradeBranch(branch); err != nil {
			return req, err
		}
		req.channel, req.branch = upgradeChannelDev, branch
	}
	return req, nil
}

// validateUpgradeVersion checks that version names a release ctrld can switch
// to from currentVersion, and returns it with a leading "v". Like the
// automatic self-upgrade, it refuses to change the major version, since that
// may break the installed configuration.
func validateUpgradeVersion(version, currentVersion string) (string, error) {
	if !upgradeVersionPattern.MatchString(version) {
		return "", fmt.Errorf("invalid version %q: want a release version such as v1.2.3", version)
	}
	v := "v" + strings.TrimPrefix(version, "v")
	target, err := semver.NewVersion(v)
	if err != nil {
		return "", fmt.Errorf("invalid version %q: %w", version, err)
	}
	// Development builds have no comparable version, so any release is allowed.
	if cur, err := semver.NewVersion(currentVersion); err == nil && cur.Major() != target.Major() {
		return "", fmt.Errorf("version %s is not supported: changing the major version from %d is not allowed", v, cur.Major())
	}
	return v, nil
}

// validateUpgradeBranch checks that branch is a branch name the download
// server accepts.
func validateUpgradeBranch(branch string) error {
	if !upgradeBranchPattern.MatchString(branch) {
		return fmt.Errorf("invalid branch %q: only letters, digits, '.', '_', '-' and '/' between names are allowed", branch)
	}
	for _, seg := range strings.Split(branch, "/") {
		if seg == ".." {
			return fmt.Errorf("invalid branch %q: '..' is not allowed", branch)
		}
	}
	return nil
}

// downloadUrl returns the url of the requested binary under baseUrl. The
// branch is sent URL-encoded, so a "/" in it stays inside the parameter.
func (r upgradeRequest) downloadUrl(baseUrl string) string {
	dlUrl := upgradeUrl(baseUrl)
	q := url.Values{}
	if r.version != "" {
		q.Set("version", strings.TrimPrefix(r.version, "v"))
	}
	if r.branch != "" {
		q.Set("branch", r.branch)
	}
	if len(q) > 0 {
		dlUrl += "?" + q.Encode()
	}
	return dlUrl
}

// describe names the requested build for log messages.
func (r upgradeRequest) describe() string {
	switch {
	case r.version != "":
		return "release " + r.version
	case r.branch != "":
		return fmt.Sprintf("latest %s build of branch %s", r.channel, r.branch)
	}
	return fmt.Sprintf("latest %s build", r.channel)
}

// verifyDownloadedVersion runs the downloaded binary and checks it reports
// version want. It stages the binary next to bin, where the installed binary
// is known to be executable.
//
// The download server serves the latest build for a parameter it does not
// understand, so this check is what keeps "--version" from silently
// installing the latest release instead of the requested one.
//
// Both the probe and the removal are retried: on Windows, an antivirus scan
// can briefly block running a file that was just written, and the image lock
// is released some time after the probe exits.
func verifyDownloadedVersion(data []byte, bin, want string) (string, error) {
	staged := bin + downloadBinSuffix
	if err := os.WriteFile(staged, data, 0755); err != nil {
		return "", fmt.Errorf("could not stage the downloaded binary: %w", err)
	}
	defer func() {
		if err := removeBinaryWithRetry(staged, upgradeStopTimeout); err != nil {
			mainLog.Load().Warn().Err(err).Msg("Could not remove the staged download")
		}
	}()
	got, err := binaryVersionWithRetry(staged, downloadProbeTimeout)
	if err != nil {
		return "", fmt.Errorf("downloaded binary does not run on this host: %w", err)
	}
	if "v"+strings.TrimPrefix(got, "v") != want {
		return got, fmt.Errorf("download server returned version %s instead of the requested %s", got, want)
	}
	return got, nil
}

// logVersionChange records a completed version change. It is logged at
// notice level with the action and both versions as fields, so the change can
// be audited from the command's output.
func logVersionChange(action, from, to string) {
	mainLog.Load().Notice().
		Str("action", action).
		Str("from", from).
		Str("to", to).
		Msgf("%s successful - %s", capitalize(action), to)
}

// capitalize returns s with its first byte upper-cased.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// newRollbackRequest validates the "ctrld-client rollback" flags. A branch selects
// the latest build of that branch from the dev channel; otherwise the target
// is a release from the prod channel, chosen by rollbackVersion.
func newRollbackRequest(current, version, branch string) (upgradeRequest, error) {
	switch {
	case version != "" && branch != "":
		return upgradeRequest{}, errVersionWithBranch
	case branch != "":
		if err := validateUpgradeBranch(branch); err != nil {
			return upgradeRequest{}, err
		}
		return upgradeRequest{channel: upgradeChannelDev, branch: branch}, nil
	}
	v, err := rollbackVersion(current, version)
	if err != nil {
		return upgradeRequest{}, err
	}
	return upgradeRequest{channel: upgradeChannelProd, version: v}, nil
}

// rollbackVersion returns the release "ctrld-client rollback" installs over
// current: version when given, or else the release before current. A given
// version is validated like "ctrld-client upgrade --version", and must be older than
// current when current is a release.
func rollbackVersion(current, version string) (string, error) {
	if version == "" {
		return previousRelease(current)
	}
	v, err := validateUpgradeVersion(version, current)
	if err != nil {
		return "", err
	}
	if cur, err := semver.NewVersion(current); err == nil && cur.Prerelease() == "" {
		if target := semver.MustParse(v); !target.LessThan(cur) {
			return "", fmt.Errorf(`%s is not older than the installed %s; use "ctrld-client upgrade prod --version" to upgrade`, v, current)
		}
	}
	return v, nil
}

// previousRelease returns the release before current: the same major and
// minor version with the patch version one lower. The release before an x.y.0
// is the last patch of an earlier minor version, which ctrld cannot know
// without a list of releases, so that and a development build are errors.
func previousRelease(current string) (string, error) {
	cur, err := semver.NewVersion(current)
	if err != nil || cur.Prerelease() != "" || cur.Metadata() != "" {
		return "", fmt.Errorf(`%s is not a release build; use "ctrld-client rollback --version" to choose the release`, current)
	}
	if cur.Patch() == 0 {
		return "", fmt.Errorf(`the release before %s is not known; use "ctrld-client rollback --version" to choose the release`, current)
	}
	return fmt.Sprintf("v%d.%d.%d", cur.Major(), cur.Minor(), cur.Patch()-1), nil
}

// runningVersionTarget asks the running service for the version target the
// Control D API last returned for this device. It returns "" when no target
// is set, or when there is no running service to ask.
func runningVersionTarget() string {
	s, _, err := NewServiceCommand().initializeServiceManager()
	if err != nil || s == nil {
		return ""
	}
	dir, _ := socketDir()
	if dir == "" {
		return ""
	}
	cc := newSocketControlClient(context.TODO(), s, dir)
	if cc == nil {
		return ""
	}
	resp, err := cc.post(versionTargetPath, nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return strings.TrimSpace(string(buf))
}

// warnVersionTargetOverride warns before a release is installed on a device
// whose version target, read by lookup, would upgrade it again. Each API
// config refresh runs the automatic upgrade with that target, so this asks
// shouldUpgrade the same question about the release being installed. Branch
// builds are skipped: the automatic upgrade never runs on non-release builds.
func warnVersionTargetOverride(req upgradeRequest, lookup func() string) {
	if req.version == "" {
		return
	}
	target := lookup()
	if target == "" {
		return
	}
	installed, err := semver.NewVersion(req.version)
	if err != nil {
		return
	}
	if !shouldUpgrade(target, installed, ctrld.NopLogger) {
		return
	}
	mainLog.Load().Warn().Msgf("The dashboard version target of this device is %s, above %s: "+
		"ctrld upgrades again at the next config refresh (every hour by default). "+
		"Clear or lower the version target in the dashboard to stay on %s.", target, req.version, req.version)
}

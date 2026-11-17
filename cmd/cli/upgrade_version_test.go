package cli

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestNewUpgradeRequest(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		version        string
		branch         string
		defaultChannel string
		current        string
		want           upgradeRequest
		wantErr        string
	}{
		{name: "default channel", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelProd}},
		{name: "explicit dev", args: []string{"dev"}, defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelDev}},
		{name: "unknown channel", args: []string{"beta"}, defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: "upgrade argument must be"},

		{name: "version picks prod", version: "v1.5.7", defaultChannel: upgradeChannelDev, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"}},
		{name: "version without v", args: []string{"prod"}, version: "1.5.7", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"}},
		{name: "newer version", args: []string{"prod"}, version: "v1.6.0", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelProd, version: "v1.6.0"}},
		{name: "version from a dev build", args: []string{"prod"}, version: "v1.5.7", defaultChannel: upgradeChannelDev, current: "dev-abc1234",
			want: upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"}},
		{name: "version on dev channel", args: []string{"dev"}, version: "v1.5.7", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: `"--version" can only be used with "ctrld upgrade prod"`},
		{name: "major version change", args: []string{"prod"}, version: "v2.0.0", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: "changing the major version"},
		{name: "major version downgrade", args: []string{"prod"}, version: "v0.9.0", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: "changing the major version"},

		{name: "branch picks dev", branch: "master", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelDev, branch: "master"}},
		{name: "branch with slash", args: []string{"dev"}, branch: "devscribe/foo", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelDev, branch: "devscribe/foo"}},
		{name: "release branch", args: []string{"dev"}, branch: "v1.0", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			want: upgradeRequest{channel: upgradeChannelDev, branch: "v1.0"}},
		{name: "branch on prod channel", args: []string{"prod"}, branch: "master", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: `"--branch" can only be used with "ctrld upgrade dev"`},

		{name: "version and branch", args: []string{"prod"}, version: "v1.5.7", branch: "master", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: `"--version" and "--branch" cannot be used together`},
		{name: "version and branch without channel", version: "v1.5.7", branch: "master", defaultChannel: upgradeChannelProd, current: "v1.5.8",
			wantErr: `"--version" and "--branch" cannot be used together`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newUpgradeRequest(tc.args, tc.version, tc.branch, tc.defaultChannel, tc.current)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("request = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidateUpgradeVersionRejectsInvalid(t *testing.T) {
	for _, v := range []string{
		"", "latest", "1.5", "v1", "1.5.7.1", "v1.5.7-rc1", "V1.5.7", "vv1.5.7",
		" 1.5.7", "1.5.7\n", "1.5.7?branch=x", "../1.5.7", "1.5.x",
	} {
		if got, err := validateUpgradeVersion(v, "v1.5.8"); err == nil {
			t.Errorf("validateUpgradeVersion(%q) = %q, want an error", v, got)
		}
	}
}

func TestValidateUpgradeBranch(t *testing.T) {
	for _, b := range []string{"master", "v1.0", "issue-623", "devscribe/fix-tailscale-retry-test-race-v1.0", "a/b/c", "a.b_c-d"} {
		if err := validateUpgradeBranch(b); err != nil {
			t.Errorf("validateUpgradeBranch(%q) = %v, want nil", b, err)
		}
	}
	for _, b := range []string{"", "..", "a/../b", "a/..", "/a", "a/", "a//b", "a b", "a?b", "a%2Fb", "a&version=1.5.7", "a\\b"} {
		if err := validateUpgradeBranch(b); err == nil {
			t.Errorf("validateUpgradeBranch(%q) = nil, want an error", b)
		}
	}
}

func TestUpgradeRequestDownloadUrl(t *testing.T) {
	const base = "https://dl.controld.com"
	plain := upgradeUrl(base)
	tests := []struct {
		req       upgradeRequest
		wantQuery url.Values
		wantRaw   string
	}{
		{req: upgradeRequest{channel: upgradeChannelProd}},
		{req: upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"},
			wantQuery: url.Values{"version": {"1.5.7"}}, wantRaw: "version=1.5.7"},
		{req: upgradeRequest{channel: upgradeChannelDev, branch: "devscribe/foo"},
			wantQuery: url.Values{"branch": {"devscribe/foo"}}, wantRaw: "branch=devscribe%2Ffoo"},
	}
	for _, tc := range tests {
		got := tc.req.downloadUrl(base)
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("downloadUrl(%+v) = %q: %v", tc.req, got, err)
		}
		if path, _, _ := strings.Cut(got, "?"); path != plain {
			t.Errorf("downloadUrl(%+v) path = %q, want %q", tc.req, path, plain)
		}
		if u.RawQuery != tc.wantRaw {
			t.Errorf("downloadUrl(%+v) query = %q, want %q", tc.req, u.RawQuery, tc.wantRaw)
		}
		if tc.wantQuery != nil && u.Query().Encode() != tc.wantQuery.Encode() {
			t.Errorf("downloadUrl(%+v) decoded query = %v, want %v", tc.req, u.Query(), tc.wantQuery)
		}
	}
}

func TestVerifyDownloadedVersion(t *testing.T) {
	data := []byte("downloaded binary")
	tests := []struct {
		name     string
		reported string
		probeErr error
		failures int // probes that fail before one succeeds, as during an antivirus scan
		wantErr  string
	}{
		{name: "matching version", reported: "v1.5.7"},
		{name: "matching version without v", reported: "1.5.7"},
		// The download server ignored the version and served the latest.
		{name: "latest served instead", reported: "v1.5.8", wantErr: "instead of the requested v1.5.7"},
		{name: "binary does not run", probeErr: errors.New("exec format error"), wantErr: "does not run on this host"},
		{name: "probe blocked briefly", reported: "v1.5.7", failures: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "ctrld")
			staged := bin + downloadBinSuffix
			var probed string
			prev := binaryVersionFn
			binaryVersionFn = func(path string) (string, error) {
				if path != staged {
					t.Errorf("probed %q, want the staged file %q", path, staged)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("staged file not readable: %v", err)
				}
				probed = string(b)
				if tc.failures > 0 {
					tc.failures--
					return "", errors.New("file is being scanned")
				}
				return tc.reported, tc.probeErr
			}
			t.Cleanup(func() { binaryVersionFn = prev })

			_, err := verifyDownloadedVersion(data, bin, "v1.5.7")
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
			}
			if probed != string(data) {
				t.Errorf("probed content = %q, want the downloaded bytes", probed)
			}
			if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("staged file left behind: %v", err)
			}
		})
	}
}

func TestPreviousRelease(t *testing.T) {
	for cur, want := range map[string]string{
		"v1.5.8":  "v1.5.7",
		"1.5.1":   "v1.5.0",
		"v2.10.3": "v2.10.2",
	} {
		got, err := previousRelease(cur)
		if err != nil || got != want {
			t.Errorf("previousRelease(%q) = (%q, %v), want %q", cur, got, err, want)
		}
	}
	for cur, wantErr := range map[string]string{
		"v1.6.0":           "release before v1.6.0 is not known",
		"v1.0.0":           "release before v1.0.0 is not known",
		"dev-abc1234":      "not a release build",
		"v1.5.8-rc1":       "not a release build",
		"v1.5.8+build.1":   "not a release build",
		"":                 "not a release build",
		"v1.5.8-dev-a1b2c": "not a release build",
	} {
		got, err := previousRelease(cur)
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("previousRelease(%q) = (%q, %v), want an error containing %q", cur, got, err, wantErr)
		}
	}
}

func TestRollbackVersion(t *testing.T) {
	tests := []struct {
		current, version string
		want, wantErr    string
	}{
		{current: "v1.5.8", want: "v1.5.7"},
		{current: "v1.6.0", wantErr: "release before v1.6.0 is not known"},
		{current: "v1.5.8", version: "v1.5.7", want: "v1.5.7"},
		{current: "v1.5.8", version: "1.4.2", want: "v1.4.2"},
		{current: "v1.6.0", version: "v1.5.8", want: "v1.5.8"},
		{current: "dev-abc1234", version: "v1.5.7", want: "v1.5.7"},
		{current: "v1.5.8-rc1", version: "v1.5.7", want: "v1.5.7"},
		{current: "v1.5.8", version: "v1.5.8", wantErr: "not older than the installed v1.5.8"},
		{current: "v1.5.8", version: "v1.6.0", wantErr: "not older than the installed v1.5.8"},
		{current: "v1.5.8", version: "v0.9.0", wantErr: "changing the major version"},
		{current: "v1.5.8", version: "latest", wantErr: "invalid version"},
	}
	for _, tc := range tests {
		got, err := rollbackVersion(tc.current, tc.version)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("rollbackVersion(%q, %q) = (%q, %v), want an error containing %q", tc.current, tc.version, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("rollbackVersion(%q, %q) = (%q, %v), want %q", tc.current, tc.version, got, err, tc.want)
		}
	}
}

func TestNewRollbackRequest(t *testing.T) {
	tests := []struct {
		version, branch string
		want            upgradeRequest
		wantErr         string
	}{
		{want: upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"}},
		{version: "1.4.2", want: upgradeRequest{channel: upgradeChannelProd, version: "v1.4.2"}},
		{branch: "devscribe/foo", want: upgradeRequest{channel: upgradeChannelDev, branch: "devscribe/foo"}},
		{branch: "v1.0", want: upgradeRequest{channel: upgradeChannelDev, branch: "v1.0"}},
		{branch: "a/../b", wantErr: "'..' is not allowed"},
		{branch: "a b", wantErr: "invalid branch"},
		{version: "v1.5.7", branch: "master", wantErr: `"--version" and "--branch" cannot be used together`},
		{version: "v1.6.0", wantErr: "not older than the installed v1.5.8"},
	}
	for _, tc := range tests {
		got, err := newRollbackRequest("v1.5.8", tc.version, tc.branch)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("newRollbackRequest(%q, %q) = (%+v, %v), want an error containing %q", tc.version, tc.branch, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("newRollbackRequest(%q, %q) = (%+v, %v), want %+v", tc.version, tc.branch, got, err, tc.want)
		}
	}
}

// TestBinarySwitchInstall installs a binary with no service installed, and
// checks that it replaces the installed one and that no copy of the replaced
// binary is left behind once the switch succeeded.
func TestBinarySwitchInstall(t *testing.T) {
	stubBinaryVersion(t, "v1.5.7", nil)
	bin := filepath.Join(t.TempDir(), "ctrld")
	if err := os.WriteFile(bin, []byte("v1.5.8 binary"), 0755); err != nil {
		t.Fatal(err)
	}
	sw := &binarySwitch{bin: bin, oldBin: bin + oldBinSuffix}

	sw.install("rollback", []byte("v1.5.7 binary"))

	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1.5.7 binary" {
		t.Errorf("installed binary holds %q, want the new binary", got)
	}
	if _, err := os.Stat(sw.oldBin); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("replaced binary kept at %s: %v", sw.oldBin, err)
	}
}

func TestWarnVersionTargetOverride(t *testing.T) {
	orig := mainLog.Load()
	t.Cleanup(func() { mainLog.Store(orig) })
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	mainLog.Store(&logger)

	release := upgradeRequest{channel: upgradeChannelProd, version: "v1.5.7"}
	lookup := func(target string) func() string {
		return func() string { return target }
	}
	tests := []struct {
		name   string
		req    upgradeRequest
		lookup func() string
		want   string // substring of the warning, or empty for none
	}{
		{name: "target above", req: release, lookup: lookup("1.5.8"),
			want: "version target of this device is 1.5.8, above v1.5.7"},
		{name: "target above with v", req: release, lookup: lookup("v1.6.0"),
			want: "version target of this device is v1.6.0, above v1.5.7"},
		{name: "target equal", req: release, lookup: lookup("1.5.7")},
		{name: "target below", req: release, lookup: lookup("1.5.0")},
		// Also what a missing service, or one predating the endpoint, gives.
		{name: "no target", req: release, lookup: lookup("")},
		// The automatic upgrade never changes the major version.
		{name: "target in another major", req: release, lookup: lookup("2.0.0")},
		{name: "branch build", req: upgradeRequest{channel: upgradeChannelDev, branch: "master"},
			lookup: func() string {
				t.Error("version target looked up for a branch build")
				return "1.5.8"
			}},
		{name: "latest", req: upgradeRequest{channel: upgradeChannelProd},
			lookup: func() string {
				t.Error("version target looked up for the latest build")
				return "1.5.8"
			}},
	}
	for _, tc := range tests {
		buf.Reset()
		warnVersionTargetOverride(tc.req, tc.lookup)
		got := buf.String()
		if tc.want == "" {
			if got != "" {
				t.Errorf("%s: logged %q, want nothing", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, `"level":"warn"`) || !strings.Contains(got, tc.want) {
			t.Errorf("%s: logged %q, want a warning containing %q", tc.name, got, tc.want)
		}
	}
}

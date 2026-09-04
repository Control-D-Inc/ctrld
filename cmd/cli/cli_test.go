package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_writeConfigFile(t *testing.T) {
	tmpdir := t.TempDir()
	// simulate --config CLI flag by setting configPath manually.
	configPath = filepath.Join(tmpdir, "ctrld.toml")
	_, err := os.Stat(configPath)
	assert.True(t, os.IsNotExist(err))

	assert.NoError(t, writeConfigFile(&cfg))

	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

func Test_isStableVersion(t *testing.T) {
	tests := []struct {
		name     string
		ver      string
		isStable bool
	}{
		{"stable", "v1.3.5", true},
		{"pre", "v1.3.5-next", false},
		{"pre with commit hash", "v1.3.5-next-asdf", false},
		{"dev", "dev", false},
		{"empty", "dev", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isStableVersion(tc.ver); got != tc.isStable {
				t.Errorf("unexpected result for %s, want: %v, got: %v", tc.ver, tc.isStable, got)
			}
		})
	}
}

// Test_displayVersion pins the tag-to-display transform. master carries v2.x.x
// tags so its releases can be tracked next to the v1.x.x line still cut from the
// v1.0 branch, and the client reports the tag with its major decremented.
//
// The v1.0-branch cases are the ones that make the split safe without a
// build-time branch signal: a major of 1 has to pass through untouched, or the
// v1.0 line would start reporting v0.x.x.
func Test_displayVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"master tag", "v2.0.0", "v1.0.0"},
		{"master tag with minor and patch", "v2.3.1", "v1.3.1"},
		{"master prerelease keeps its suffix", "v2.1.0-rc1", "v1.1.0-rc1"},
		{"master tag with build metadata", "v2.1.0+build.5", "v1.1.0+build.5"},
		{"a later major still decrements by one", "v3.2.1", "v2.2.1"},
		// v1.0 branch: untouched, which is what scopes the transform to master.
		{"v1.0 branch tag", "v1.3.5", "v1.3.5"},
		{"v1.0 branch prerelease", "v1.3.5-next", "v1.3.5-next"},
		// Not semantic versions: dev and commit-suffixed builds pass through.
		{"dev", "dev", "dev"},
		{"dev with commit", "dev-abc1234", "dev-abc1234"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := displayVersion(tc.in); got != tc.want {
				t.Errorf("displayVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Test_displayVersionKeepsStabilityClassification guards the coupling between the
// transform and isStableVersion, which selects the self-upgrade channel: a tag
// must not change from prerelease to stable (or back) by being renumbered.
func Test_displayVersionKeepsStabilityClassification(t *testing.T) {
	for _, ver := range []string{"v2.0.0", "v2.1.0-rc1", "v1.3.5", "v1.3.5-next", "dev"} {
		ver := ver
		t.Run(ver, func(t *testing.T) {
			t.Parallel()
			if got, want := isStableVersion(displayVersion(ver)), isStableVersion(ver); got != want {
				t.Errorf("isStableVersion(displayVersion(%q)) = %v, want %v", ver, got, want)
			}
		})
	}
}

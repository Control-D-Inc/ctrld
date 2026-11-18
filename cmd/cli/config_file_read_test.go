package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// On mobile, the process is the app. A config file that ctrld cannot read
// must fail the start with a code, and must not end the process. This holds
// for config.toml too, which ctrld reads with writeDefaultConfig false.
func TestReadConfigFileOnMobileFailsTheStartForABadFile(t *testing.T) {
	notTOML := func(t *testing.T, path string) {
		require.NoError(t, os.WriteFile(path, []byte("[listener.0"), 0o600))
	}
	folder := func(t *testing.T, path string) {
		require.NoError(t, os.Mkdir(path, 0o700))
	}
	tests := []struct {
		name               string
		makeFile           func(t *testing.T, path string)
		writeDefaultConfig bool
		wantMessage        string
	}{
		{"not TOML", notTOML, true, "Failed to decode config file at line: 1, column: 12"},
		{"not TOML, config.toml", notTOML, false, "Failed to decode config file at line: 1, column: 12"},
		{"cannot be read", folder, true, "Failed to decode config file: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitCode := stubMobileConfigRead(t)
			path := filepath.Join(t.TempDir(), "ctrld.toml")
			tc.makeFile(t, path)
			v.SetConfigFile(path)

			require.False(t, readConfigFile(tc.writeDefaultConfig, false))

			r := pendingProvisionFailure.Load()
			require.NotNil(t, r, "no failure was recorded")
			require.Equal(t, string(provisionCodeUnclassified), r.Code)
			require.Contains(t, r.Message, tc.wantMessage)
			require.Equal(t, -1, *exitCode, "the process exited")
		})
	}
}

// The app may start with no config file. That is not a failure of the read,
// whether ctrld looks the file up by name or gets its path.
func TestReadConfigFileOnMobileAcceptsNoFile(t *testing.T) {
	tests := []struct {
		name   string
		locate func(dir string)
	}{
		{"by name", func(dir string) { ctrld.SetConfigNameWithPath(v, "config", dir) }},
		{"by path", func(dir string) { v.SetConfigFile(filepath.Join(dir, "ctrld.toml")) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubMobileConfigRead(t)
			tc.locate(t.TempDir())

			require.False(t, readConfigFile(false, false))

			require.Nil(t, pendingProvisionFailure.Load())
		})
	}
}

func stubMobileConfigRead(t *testing.T) *int {
	t.Helper()
	exitCode, _ := stubProvisionGlobals(t)
	useConfigPath(t, "")
	oldIsMobile := isMobile
	t.Cleanup(func() {
		isMobile = oldIsMobile
		pendingProvisionFailure.Store(nil)
	})
	isMobile = func() bool { return true }
	return exitCode
}

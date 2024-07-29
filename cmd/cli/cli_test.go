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

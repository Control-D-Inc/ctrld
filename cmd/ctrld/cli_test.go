package main

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

	assert.NoError(t, writeConfigFile())

	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

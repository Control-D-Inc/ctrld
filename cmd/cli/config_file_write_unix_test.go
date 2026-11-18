//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// A root process that rewrites the config file of a user must not take the
// file from that user. The test changes only the group, which a user can do
// for each group that the user is in.
func TestWriteConfigFileKeepsTheOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.toml")
	useConfigPath(t, path)
	require.NoError(t, os.WriteFile(path, []byte(oldConfigContent), 0o600))
	group := otherGroup(t, path)
	require.NoError(t, os.Chown(path, -1, group))

	require.NoError(t, writeConfigFile(newTestConfig()))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, uint32(group), fi.Sys().(*syscall.Stat_t).Gid)
}

// A new config file gets 0644, less the umask. The file holds the resolver
// UID, so a strict umask must keep others out.
func TestWriteConfigFileCreatesAFileWithTheUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.toml")
	useConfigPath(t, path)
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	require.NoError(t, writeConfigFile(newTestConfig()))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

// otherGroup returns a group that this user can give to path, other than the
// group that path has now.
func otherGroup(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	current := int(fi.Sys().(*syscall.Stat_t).Gid)
	if os.Geteuid() == 0 && current != 1 {
		return 1
	}
	groups, err := os.Getgroups()
	require.NoError(t, err)
	for _, g := range groups {
		if g != current {
			return g
		}
	}
	t.Skip("this user is in no other group")
	return 0
}

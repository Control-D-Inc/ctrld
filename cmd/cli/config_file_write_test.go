package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

const oldConfigContent = "# old config\n"

// useConfigPath points the config file globals at path for one test.
func useConfigPath(t *testing.T, path string) {
	t.Helper()
	oldV, oldFile, oldPath, oldUID := v, defaultConfigFile, configPath, cdUID
	t.Cleanup(func() { v, defaultConfigFile, configPath, cdUID = oldV, oldFile, oldPath, oldUID })
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	configPath, cdUID = path, ""
}

func newTestConfig() *ctrld.Config {
	return &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: "doh", Endpoint: "https://dns.controld.com/test"}}}
}

// iOS or Android can end the app while it writes the config file. A write in
// place can then leave a cut-short file, which fails each later start. The
// new content must go to a new file that replaces the old one in one step,
// so the old file stays whole until then.
func TestWriteConfigFileReplacesTheFileInOneStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.toml")
	useConfigPath(t, path)
	require.NoError(t, os.WriteFile(path, []byte(oldConfigContent), 0o600))
	oldFile := filepath.Join(dir, "old-file")
	require.NoError(t, os.Link(path, oldFile))

	require.NoError(t, writeConfigFile(newTestConfig()))

	old, err := os.ReadFile(oldFile)
	require.NoError(t, err)
	require.Equal(t, oldConfigContent, string(old), "the write changed the old file in place")
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(written), "https://dns.controld.com/test")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{"ctrld.toml", "old-file"}, names, "a temporary file stayed")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "the write changed the file mode")
	}
}

// An operator can keep the config elsewhere and link to it. The write must
// change the file that the link names, and keep the link, also when that
// file does not exist yet.
func TestWriteConfigFileFollowsASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symlink needs a privilege on Windows")
	}
	for _, targetExists := range []bool{true, false} {
		t.Run(fmt.Sprintf("target exists %v", targetExists), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "real.toml")
			if targetExists {
				require.NoError(t, os.WriteFile(target, []byte(oldConfigContent), 0o644))
			}
			link := filepath.Join(t.TempDir(), "ctrld.toml")
			require.NoError(t, os.Symlink(target, link))
			useConfigPath(t, link)

			require.NoError(t, writeConfigFile(newTestConfig()))

			fi, err := os.Lstat(link)
			require.NoError(t, err)
			require.NotZero(t, fi.Mode()&os.ModeSymlink, "the write replaced the link with a file")
			written, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Contains(t, string(written), "https://dns.controld.com/test")
		})
	}
}

// Some config files cannot be replaced: a file in a folder that ctrld cannot
// write, or a file mounted on its own in a container, where the rename
// fails. ctrld must still write them, in place.
func TestWriteConfigFileWritesInPlaceWhenItCannotReplace(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"folder not writable", func(t *testing.T, dir string) {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("the folder mode does not stop this user from writing")
			}
			require.NoError(t, os.Chmod(dir, 0o500))
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		}},
		{"rename fails", func(t *testing.T, dir string) {
			old := renameFile
			t.Cleanup(func() { renameFile = old })
			renameFile = func(string, string) error { return errors.New("device or resource busy") }
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ctrld.toml")
			useConfigPath(t, path)
			require.NoError(t, os.WriteFile(path, []byte(oldConfigContent), 0o600))
			tc.setup(t, dir)

			require.NoError(t, writeConfigFile(newTestConfig()))

			written, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Contains(t, string(written), "https://dns.controld.com/test")
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1, "a temporary file stayed")
		})
	}
}

// A write that stopped, for example because iOS ended the app, leaves its
// temporary file. A later write removes it. A young temporary file can
// belong to a write that runs now, so it stays.
func TestWriteConfigFileRemovesOldTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.toml")
	useConfigPath(t, path)
	stale := filepath.Join(dir, "ctrld.toml.tmpstale")
	young := filepath.Join(dir, "ctrld.toml.tmpyoung")
	other := filepath.Join(dir, "other.toml.tmpstale")
	for _, f := range []string{stale, young, other} {
		require.NoError(t, os.WriteFile(f, nil, 0o600))
	}
	longAgo := time.Now().Add(-2 * staleTempFileAge)
	for _, f := range []string{stale, other} {
		require.NoError(t, os.Chtimes(f, longAgo, longAgo))
	}

	require.NoError(t, writeConfigFile(newTestConfig()))

	require.NoFileExists(t, stale)
	require.FileExists(t, young)
	require.FileExists(t, other)
}

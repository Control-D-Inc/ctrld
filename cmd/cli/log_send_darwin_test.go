package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// These tests touch only owned temporary files and sockets: no service, PF,
// DNS, elevation, or Control D network calls. Execute on native macOS.
func TestDelegatedLogSendDarwinACL(t *testing.T) {
	tree, c := logSendFixture(t)
	if got := readDelegated(t, c); got != "89abcdef" {
		t.Fatal(got)
	}
	for _, target := range []string{c.config, c.sources[0].path, tree.root} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			cmd := exec.Command("/bin/chmod", "+a", "everyone allow read", target)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("set temp ACL: %v: %s", err, out)
			}
			defer func() {
				if out, err := exec.Command("/bin/chmod", "-N", target).CombinedOutput(); err != nil {
					t.Errorf("remove temp ACL: %v: %s", err, out)
				}
			}()
			if r, err := c.collect(context.Background()); err == nil {
				r.Close()
				t.Fatal("extended ACL accepted")
			}
		})
	}
}

func TestDelegatedLogSendDarwinProductionParent(t *testing.T) {
	// Read only: exercise the actual ancestor chain, not a 0700 temp substitute.
	tree := trustedLogTree{root: "/", uid: 0}
	parent, err := tree.open(filepath.Dir(logSendSocketDir), true)
	if err != nil {
		t.Fatalf("production socket parent is not trusted: %v", err)
	}
	parent.Close()
}

func TestDelegatedLogSendDarwinWritableParent(t *testing.T) {
	tree, _ := logSendFixture(t)
	parent := filepath.Join(tree.root, "run")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	// Chmod after mkdir makes the fixture independent of the runner's umask.
	if err := os.Chmod(parent, 0775); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "socket")
	if l, err := listenDelegatedLogSend(tree, dir); !errors.Is(err, errLogSendTrust) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("group-writable parent listener error=%v", err)
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if c, err := dialLogSend(context.Background(), tree, filepath.Join(dir, "send.sock")); !errors.Is(err, errLogSendTrust) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("group-writable parent dial error=%v", err)
	}
	st, err := os.Stat(parent)
	if err != nil || st.Mode().Perm() != 0775 {
		t.Fatalf("parent permissions were changed: %v, %v", st, err)
	}
}

func TestDelegatedLogSendDarwinEmptyStartup(t *testing.T) {
	tree, collector := logSendFixture(t)
	writeLogSendFixture(t, collector.sources[0].path, "")
	dir := filepath.Join(tree.root, "socket")
	l, err := collector.listen(dir)
	if err != nil {
		t.Fatalf("empty trusted logs prevent listener startup: %v", err)
	}
	s := &logSendServer{gate: &logUploadGate{}, collect: collector.collect,
		upload: func(context.Context, io.ReadCloser) error { t.Error("uploaded empty logs"); return nil },
	}
	s.serve(l, logSendPeer)
	t.Cleanup(s.stop)
	err = requestDelegatedLogSend(context.Background(), false, func(ctx context.Context) (net.Conn, error) {
		return dialLogSend(ctx, tree, filepath.Join(dir, "send.sock"))
	})
	if err == nil || !strings.Contains(err.Error(), "administrator must check") {
		t.Fatalf("empty upload should return a precondition error: %v", err)
	}
	s.stop()
	writeLogSendFixture(t, collector.config, "[service]\nallow_unprivileged_log_send = false\n")
	if l, err := collector.listen(dir); err == nil {
		l.Close()
		t.Fatal("disabled config exposed a listener")
	}
}

func TestDelegatedLogSendDarwinListenerLifecycle(t *testing.T) {
	tree, _ := logSendFixture(t)
	dir := filepath.Join(tree.root, "socket")
	l, err := listenDelegatedLogSend(tree, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "send.sock")
	st, err := os.Stat(path)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0666 {
		t.Errorf("socket mode=%o", st.Mode().Perm())
	}
	if other, err := listenDelegatedLogSend(tree, dir); err == nil {
		other.Close()
		t.Error("replaced live listener")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket retained: %v", err)
	}
	if err := os.Symlink(tree.root, dir+"-alias"); err != nil {
		t.Fatal(err)
	}
	if other, err := listenDelegatedLogSend(tree, dir+"-alias"); err == nil {
		other.Close()
		t.Fatal("symlink parent accepted")
	}
}

func TestDelegatedLogSendConfigPathAfterCustomConfig(t *testing.T) {
	oldV, oldFile, oldPath := v, defaultConfigFile, configPath
	t.Cleanup(func() { v, defaultConfigFile, configPath = oldV, oldFile, oldPath })

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "ctrld.toml")
	if err := os.WriteFile(onDisk, []byte("[service]\nallow_unprivileged_log_send = true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Service start: --config names the file and readConfigFile reads it.
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	configPath, defaultConfigFile = onDisk, onDisk
	v.SetConfigFile(onDisk)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if got := configFileForWrite(); got != onDisk {
		t.Fatalf("file config: got %q, want %q", got, onDisk)
	}

	// --cd with a custom config: the production loader replaces viper with an
	// in-memory config, so viper no longer names any file.
	custom := base64.StdEncoding.EncodeToString([]byte("[service]\nallow_unprivileged_log_send = true\n"))
	if err := readBase64Config(custom); err != nil {
		t.Fatal(err)
	}
	if v.ConfigFileUsed() != "" {
		t.Fatalf("precondition: viper still names %q", v.ConfigFileUsed())
	}
	for _, tc := range []struct{ name, configPath, defaultFile string }{
		{"service --config", onDisk, "ctrld.toml"},
		{"default config file", "", onDisk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath, defaultConfigFile = tc.configPath, tc.defaultFile
			if got := configFileForWrite(); got != onDisk {
				t.Fatalf("custom config: got %q, want %q", got, onDisk)
			}
		})
	}
}

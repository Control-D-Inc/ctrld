package cli

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld/internal/mobile"
)

// TestIOSRunStartsNoTools runs the library from start to stop as an iOS app
// does: listeners, postRun, and the stop. No system tool may start. The fake
// tools in PATH catch the tools that ctrld finds by name, and the CPU time of
// child processes catches the tools that it starts by absolute path. The run
// leaves package state behind, so it runs in its own process.
func TestIOSRunStartsNoTools(t *testing.T) {
	const childEnv = "CTRLD_TEST_IOS_RUN"
	if os.Getenv(childEnv) == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIOSRunStartsNoTools$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}

	marker := fakeHostTools(t)
	mobile.IsIOS = func() bool { return true }
	isMobile = func() bool { return true }
	runningAsService = func() bool { return true }
	networkUp = func(<-chan struct{}) bool { return true }
	provisionExit = func(code int) { t.Fatalf("process exit %d on mobile", code) }
	postRunDone := make(chan struct{})
	postRunFn = func(p *prog) {
		(*prog).postRun(p)
		close(postRunDone)
	}
	// A short directory keeps the control socket below the path limit of macOS.
	dir, err := os.MkdirTemp("", "ctrld-ios-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := held.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, held.Close())
	configPath = filepath.Join(dir, "ctrld.toml")
	upstream := startTestUpstream(t)
	config := "[service]\n[listener.0]\nip = \"127.0.0.1\"\nport = " + strconv.Itoa(port) +
		"\n[network.0]\ncidrs = [\"127.0.0.0/8\"]\n[upstream.0]\ntype = \"legacy\"\nendpoint = \"" + upstream + "\"\n"
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	var before syscall.Rusage
	require.NoError(t, syscall.Getrusage(syscall.RUSAGE_CHILDREN, &before))

	var exits []string
	callback := AppCallback{Exit: func(line string) { exits = append(exits, line) }}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunMobile(&AppConfig{HomeDir: dir, Verbose: -1}, &callback, stopCh)
	}()
	select {
	case <-postRunDone:
	case <-done:
		t.Fatalf("the run ended before postRun, exits: %q", exits)
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not reach postRun")
	}
	close(stopCh)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run did not end after the stop")
	}

	require.Empty(t, exits)
	requireNoHostTools(t, marker)
	var after syscall.Rusage
	require.NoError(t, syscall.Getrusage(syscall.RUSAGE_CHILDREN, &after))
	require.Equal(t, before.Utime, after.Utime, "a child process ran")
	require.Equal(t, before.Stime, after.Stime, "a child process ran")
}

// startTestUpstream serves DNS on a local UDP port, with an empty answer for
// each query, and returns its address.
func startTestUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(req)
		_ = w.WriteMsg(answer)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

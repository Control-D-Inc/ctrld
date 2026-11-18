//go:build darwin || linux

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ctrld "github.com/Control-D-Inc/ctrld"
	"golang.org/x/sys/unix"
)

func logSendFixture(t *testing.T) (trustedLogTree, delegatedLogCollector) {
	t.Helper()
	// Short names also fit Darwin's 104-byte unix socket path limit.
	dir, err := os.MkdirTemp("", "ls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	tree := trustedLogTree{root: dir, uid: uint32(os.Geteuid())}
	c := delegatedLogCollector{tree: tree, config: filepath.Join(dir, "config.toml"), sources: []delegatedLogSource{{path: filepath.Join(dir, "debug.log"), backups: 2, budget: 8}}}
	writeLogSendFixture(t, c.config, "[service]\nallow_unprivileged_log_send = true\n")
	writeLogSendFixture(t, c.sources[0].path, "0123456789abcdef")
	return tree, c
}
func writeLogSendFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func readDelegated(t *testing.T, c delegatedLogCollector) string {
	t.Helper()
	r, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDelegatedLogCollectionStripsColor(t *testing.T) {
	_, c := logSendFixture(t)
	colored := "\x1b[34mINFO\x1b[0m ok\n\x1b[31mERROR\x1b[0m bad\n"
	writeLogSendFixture(t, c.sources[0].path, colored)
	// The budget counts raw bytes, so it must cover the escapes too.
	c.sources[0].budget = int64(len(colored))
	got := readDelegated(t, c)
	if strings.Contains(got, "\x1b") {
		t.Fatalf("delegated upload kept color codes: %q", got)
	}
	if want := "INFO ok\nERROR bad\n"; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}

func TestDelegatedLogCollectionBoundedAndPinned(t *testing.T) {
	_, c := logSendFixture(t)
	writeLogSendFixture(t, c.sources[0].path+".1", strings.Repeat("older", 100))
	if got := readDelegated(t, c); got != "89abcdef" {
		t.Fatalf("tail=%q", got)
	}
	c.sources = append(c.sources, delegatedLogSource{path: filepath.Join(c.tree.root, "journal.log"), budget: 4, backups: 2})
	writeLogSendFixture(t, c.sources[1].path, "journal-data")
	if got := readDelegated(t, c); got != "89abcdef"+logWriterLogEndMarker+"data" {
		t.Fatalf("bundle=%q", got)
	}
	r, err := c.collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// An opened upload keeps the checked inode even if a privileged rotation
	// replaces its name; it cannot switch to the replacement's bytes.
	if err := os.Rename(c.sources[0].path, c.sources[0].path+".old"); err != nil {
		t.Fatal(err)
	}
	writeLogSendFixture(t, c.sources[0].path, "replacement-secret")
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") || !bytes.HasPrefix(data, []byte("89abcdef")) {
		t.Fatalf("unpinned data: %q", data)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := c.collect(ctx); err == nil {
		r.Close()
		t.Fatal("canceled collection succeeded")
	}
}

func TestDelegatedLogCollectionTrustFailures(t *testing.T) {
	cases := map[string]func(*testing.T, *delegatedLogCollector){
		"config writable":    func(t *testing.T, c *delegatedLogCollector) { os.Chmod(c.config, 0666) },
		"log writable":       func(t *testing.T, c *delegatedLogCollector) { os.Chmod(c.sources[0].path, 0666) },
		"directory writable": func(t *testing.T, c *delegatedLogCollector) { os.Chmod(c.tree.root, 0777) },
		"wrong owner":        func(t *testing.T, c *delegatedLogCollector) { c.tree.uid++ },
		"config symlink": func(t *testing.T, c *delegatedLogCollector) {
			os.Rename(c.config, c.config+".real")
			os.Symlink(c.config+".real", c.config)
		},
		"log symlink": func(t *testing.T, c *delegatedLogCollector) {
			os.Remove(c.sources[0].path)
			os.Symlink(c.config, c.sources[0].path)
		},
		"backup symlink": func(t *testing.T, c *delegatedLogCollector) { os.Symlink(c.config, c.sources[0].path+".2") },
		"hardlink": func(t *testing.T, c *delegatedLogCollector) {
			if err := os.Link(c.sources[0].path, c.sources[0].path+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, c *delegatedLogCollector) {
			os.Remove(c.sources[0].path)
			if err := unix.Mkfifo(c.sources[0].path, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"directory as log": func(t *testing.T, c *delegatedLogCollector) {
			os.Remove(c.sources[0].path)
			os.Mkdir(c.sources[0].path, 0700)
		},
		"disabled": func(t *testing.T, c *delegatedLogCollector) {
			writeLogSendFixture(t, c.config, "[service]\nallow_unprivileged_log_send = false\n")
		},
		"absent optin":   func(t *testing.T, c *delegatedLogCollector) { writeLogSendFixture(t, c.config, "[service]\n") },
		"invalid config": func(t *testing.T, c *delegatedLogCollector) { writeLogSendFixture(t, c.config, "[service") },
		"huge config": func(t *testing.T, c *delegatedLogCollector) {
			writeLogSendFixture(t, c.config, strings.Repeat("a", (1<<20)+1))
		},
		"missing config": func(t *testing.T, c *delegatedLogCollector) { os.Remove(c.config) },
		"relative log":   func(t *testing.T, c *delegatedLogCollector) { c.sources[0].path = "debug.log" },
		"escape anchor": func(t *testing.T, c *delegatedLogCollector) {
			c.sources[0].path = filepath.Join(c.tree.root, "..", "debug.log")
		},
		"too many backups": func(t *testing.T, c *delegatedLogCollector) { c.sources[0].backups = 65 },
		"unbounded budget": func(t *testing.T, c *delegatedLogCollector) { c.sources[0].budget = 0 },
		"intermediate symlink": func(t *testing.T, c *delegatedLogCollector) {
			os.Symlink(c.tree.root, filepath.Join(c.tree.root, "alias"))
			c.sources[0].path = filepath.Join(c.tree.root, "alias", "debug.log")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, c := logSendFixture(t)
			mutate(t, &c)
			if err := c.validate(context.Background()); err == nil {
				t.Fatal("unsafe startup validation succeeded")
			}
			if r, err := c.collect(context.Background()); err == nil {
				r.Close()
				t.Fatal("unsafe collection succeeded")
			}
		})
	}
}

func startLogSendFixture(t *testing.T, s *logSendServer, peer func(net.Conn) (uint32, error)) (*http.Client, string) {
	t.Helper()
	tree, _ := logSendFixture(t)
	path := filepath.Join(tree.root, "send.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s.serve(l, peer)
	t.Cleanup(s.stop)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLogSend(ctx, tree, path) }, DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, path
}
func logSendStatus(t *testing.T, c *http.Client, method, path, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("response leaked data: %q", b)
	}
	return resp.StatusCode
}

func TestDelegatedLogSendRealTransportAndIsolation(t *testing.T) {
	_, collector := logSendFixture(t)
	var sent string
	var caller int64 = -2
	var auditCode int
	var mu sync.Mutex
	s := &logSendServer{gate: &logUploadGate{}, collect: collector.collect,
		upload: func(ctx context.Context, r io.ReadCloser) error {
			b, err := io.ReadAll(r)
			sent = string(b)
			return err
		},
		audit: func(uid int64, code int) { mu.Lock(); defer mu.Unlock(); caller, auditCode = uid, code },
	}
	client, _ := startLogSendFixture(t, s, logSendPeer)
	for _, path := range []string{"/clients", "/started", "/reload", "/deactivation", "/cd", "/iface", "/log/view", "/log/tail", "/log/send?full=1", "/log/send?url=https://attacker", "/log/send?path=/etc/passwd", "/log/send/", "/log/%73end", "//log/send"} {
		if got := logSendStatus(t, client, "POST", path, ""); got != 400 {
			t.Fatalf("%s status=%d", path, got)
		}
	}
	for _, method := range []string{"GET", "PUT", "DELETE", "CONNECT"} {
		if got := logSendStatus(t, client, method, sendLogsPath, ""); got != 400 {
			t.Fatalf("%s status=%d", method, got)
		}
	}
	if got := logSendStatus(t, client, "POST", sendLogsPath, `{"uid":"attacker","full":true}`); got != 400 {
		t.Fatal(got)
	}
	if got := logSendStatus(t, client, "POST", sendLogsPath, ""); got != 200 {
		t.Fatal(got)
	}
	if sent != "89abcdef" {
		t.Fatalf("uploaded=%q", sent)
	}
	mu.Lock()
	uid, code := caller, auditCode
	mu.Unlock()
	if uid != int64(os.Geteuid()) || code != 200 {
		t.Fatalf("audit uid=%d status=%d", uid, code)
	}
	if got := logSendStatus(t, client, "POST", sendLogsPath, ""); got != 503 {
		t.Fatal(got)
	}
}

func TestDelegatedLogSendGateSharedWithAdmin(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}, cs: &controlServer{mux: http.NewServeMux()}}
	p.registerControlServerHandler()
	entered, release := make(chan struct{}), make(chan struct{})
	var collections atomic.Int32
	s := &logSendServer{gate: &p.logUpload, collect: func(context.Context) (io.ReadCloser, error) {
		collections.Add(1)
		close(entered)
		<-release
		return io.NopCloser(strings.NewReader("data")), nil
	}, upload: func(context.Context, io.ReadCloser) error { return errors.New("secret upstream error") }}
	client, _ := startLogSendFixture(t, s, logSendPeer)
	done := make(chan int, 1)
	go func() {
		resp, err := client.Post("http://unix"+sendLogsPath, "", nil)
		if err != nil {
			done <- 0
			return
		}
		defer resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			p.cs.mux.ServeHTTP(r, httptest.NewRequest("POST", sendLogsPath+"?full=1", nil))
			if r.Code != 503 {
				t.Errorf("admin concurrent=%d", r.Code)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			req := httptest.NewRequest("POST", sendLogsPath, nil).WithContext(context.WithValue(context.Background(), logSendPeerKey{}, uint32(42)))
			s.ServeHTTP(r, req)
			if r.Code != 503 {
				t.Errorf("delegated concurrent=%d", r.Code)
			}
		}()
	}
	wg.Wait()
	close(release)
	if got := <-done; got != 502 {
		t.Fatal(got)
	}
	if collections.Load() != 1 {
		t.Fatal(collections.Load())
	}
	r := httptest.NewRecorder()
	p.cs.mux.ServeHTTP(r, httptest.NewRequest("POST", sendLogsPath, nil))
	if r.Code != 503 {
		t.Fatalf("admin failure cooldown=%d", r.Code)
	}
	// Expire the cooldown explicitly, without sleeping a minute. The actual admin
	// handler fails before an upload on an empty config, then reserves cooldown too.
	p.logUpload.mu.Lock()
	p.logUpload.next = time.Time{}
	p.logUpload.mu.Unlock()
	oldUID := cdUID
	cdUID = ""
	defer func() { cdUID = oldUID }()
	r = httptest.NewRecorder()
	p.cs.mux.ServeHTTP(r, httptest.NewRequest("POST", sendLogsPath, nil))
	if r.Code != 301 {
		t.Fatalf("empty admin=%d", r.Code)
	}
	if got := logSendStatus(t, client, "POST", sendLogsPath, ""); got != 503 {
		t.Fatalf("delegated after admin=%d", got)
	}
}

func TestDelegatedLogSendFailureCooldownAndMissingIdentity(t *testing.T) {
	var calls int
	s := &logSendServer{gate: &logUploadGate{}, collect: func(context.Context) (io.ReadCloser, error) { calls++; return nil, errors.New("secret path") }}
	req := httptest.NewRequest("POST", sendLogsPath, nil)
	r := httptest.NewRecorder()
	s.ServeHTTP(r, req)
	if r.Code != 403 || calls != 0 {
		t.Fatalf("missing identity: code=%d calls=%d", r.Code, calls)
	}
	req = req.WithContext(context.WithValue(context.Background(), logSendPeerKey{}, uint32(501)))
	r = httptest.NewRecorder()
	s.ServeHTTP(r, req)
	if r.Code != 412 || r.Body.Len() != 0 || calls != 1 {
		t.Fatalf("collection failure: %+v calls=%d", r, calls)
	}
	r = httptest.NewRecorder()
	s.ServeHTTP(r, req)
	if r.Code != 503 || calls != 1 {
		t.Fatal("failure did not reserve cooldown")
	}
	client, _ := startLogSendFixture(t, &logSendServer{}, func(net.Conn) (uint32, error) { return 0, errors.New("no credentials") })
	if resp, err := client.Post("http://unix"+sendLogsPath, "", nil); err == nil {
		resp.Body.Close()
		t.Fatal("unverified peer accepted")
	}
}

func TestDelegatedLogSendShutdownCancelsAndJoins(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	s := &logSendServer{gate: &logUploadGate{}, collect: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("data")), nil }, upload: func(ctx context.Context, _ io.ReadCloser) error {
		close(entered)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	}}
	client, path := startLogSendFixture(t, s, logSendPeer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := client.Post("http://unix"+sendLogsPath, "", nil)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-entered
	s.stop()
	select {
	case <-exited:
	default:
		t.Fatal("stop did not join upload")
	}
	<-done
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed: %v", err)
	}
	p := &prog{}
	p.stopLogSendServer()
	if !p.logSendStopped {
		t.Fatal("startup not fenced")
	}
}

func TestDelegatedLogSendClientAndImpersonation(t *testing.T) {
	tree, _ := logSendFixture(t)
	path := filepath.Join(tree.root, "send.sock")
	var dials int
	dial := func(context.Context) (net.Conn, error) { dials++; return nil, errors.New("not running") }
	if err := requestDelegatedLogSend(context.Background(), true, dial); err == nil || dials != 0 {
		t.Fatal("full dialed")
	}
	if err := requestDelegatedLogSend(context.Background(), false, dial); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatal(err)
	}
	writeLogSendFixture(t, path, "not a socket")
	if c, err := dialLogSend(context.Background(), tree, path); err == nil {
		c.Close()
		t.Fatal("regular file accepted")
	}
	os.Remove(path)
	s := &logSendServer{gate: &logUploadGate{}, collect: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil }, upload: func(context.Context, io.ReadCloser) error { return nil }}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s.serve(l, logSendPeer)
	defer s.stop()
	if err := requestDelegatedLogSend(context.Background(), false, func(ctx context.Context) (net.Conn, error) { return dialLogSend(ctx, tree, path) }); err != nil {
		t.Fatal(err)
	}
	os.Chmod(tree.root, 0777)
	if c, err := dialLogSend(context.Background(), tree, path); err == nil {
		c.Close()
		t.Fatal("writable location accepted")
	}
	os.Chmod(tree.root, 0700)
	// A nonroot peer cannot impersonate root, even though it can create a socket
	// in its own directory. Production validation starts at /, not this test anchor.
	bad := tree
	bad.uid++
	if c, err := dialLogSend(context.Background(), bad, path); err == nil {
		c.Close()
		t.Fatal("wrong owner accepted")
	}
	os.Symlink(path, path+".alias")
	if c, err := dialLogSend(context.Background(), tree, path+".alias"); err == nil {
		c.Close()
		t.Fatal("symlink socket accepted")
	}
}

func TestDelegatedLogSendRawRequestsBounded(t *testing.T) {
	s := &logSendServer{gate: &logUploadGate{}, collect: func(context.Context) (io.ReadCloser, error) {
		t.Error("invalid request collected logs")
		return nil, errors.New("unexpected")
	}}
	_, path := startLogSendFixture(t, s, logSendPeer)
	for _, raw := range []string{
		"POST /log/send HTTP/1.1\r\nHost: unix\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"POST /log/send HTTP/1.1\r\nHost: unix\r\nContent-Length: 999999999\r\n\r\n",
		"POST /log/send HTTP/1.1\r\nHost: unix\r\nExpect: 100-continue\r\n\r\n",
		"POST /log/send HTTP/1.1\r\nHost: unix\r\nX-Large: " + strings.Repeat("x", 8192) + "\r\n\r\n",
	} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, raw)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if resp.StatusCode != 400 && resp.StatusCode != 431 {
			t.Errorf("unexpected status %d", resp.StatusCode)
		}
		resp.Body.Close()
		conn.Close()
	}
}

func TestDelegatedLogSendCanonicalAliases(t *testing.T) {
	for from, to := range map[string]string{"/var/log/ctrld.log": "/private/var/log/ctrld.log", "/etc/ctrld.toml": "/private/etc/ctrld.toml", "/private/var/log/a": "/private/var/log/a", "/Users/u/alias/log": "/Users/u/alias/log"} {
		if got := canonicalLogSendPath(from); got != to {
			t.Fatalf("%q => %q", from, got)
		}
	}
}

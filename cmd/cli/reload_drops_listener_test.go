package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// A reload does not start or stop DNS servers, so a running listener whose key
// is gone from the new config keeps getting queries. Each case starts real
// listeners, drives reloads through the real path, and then sends one query to
// listener.0. Each case runs in a subprocess because a nil dereference in the
// DNS handler ends the process.
func TestReloadThatDropsARunningListener(t *testing.T) {
	const env = "CTRLD_TEST_RELOAD_DROPS_LISTENER"
	mode := os.Getenv(env)
	if mode == "" {
		for _, mode := range []string{"api-reload", "control-server-reload", "control-server-accepted", "unserved-listener-dropped", "no-listener-config"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReloadThatDropsARunningListener$", "-test.v")
				cmd.Env = append(os.Environ(), env+"="+mode)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
			})
		}
		return
	}
	defer func() {
		if t.Failed() {
			t.Log(logOutput.String())
		}
	}()

	isMobile = func() bool { return true }
	cdUID = ""
	iface = ""
	monitorNetworkChangesFn = func(*prog, context.Context) error { return nil }
	var postCalls atomic.Int32
	postRunFn = func(*prog) { postCalls.Add(1) }
	// One slot, so the no-listener-config case can order its map change
	// before the read of the handler.
	semaphore := &chanSemaphore{ready: make(chan struct{}, 1)}
	var setSemaphore sync.Once
	serveDNSFn = func(p *prog, ctx context.Context, n string) error {
		setSemaphore.Do(func() { p.sema = semaphore })
		return p.serveDNS(ctx, n)
	}

	dir := t.TempDir()
	ports := map[string]int{"0": freeLocalPort(t), "1": freeLocalPort(t)}
	// configText gives the same service, network, and upstream sections for
	// each set of listeners, so a reload changes only the listeners.
	configText := func(listenerKeys ...string) string {
		// A TOML literal string, because a Windows path has backslashes.
		text := "[service]\nlog_path = '" + filepath.Join(dir, "ctrld.log") + "'\n" +
			"[network.0]\ncidrs = [\"127.0.0.0/8\"]\n" +
			"[upstream.0]\ntype = \"legacy\"\nendpoint = \"127.0.0.1\"\n"
		for _, key := range listenerKeys {
			text += "[listener." + key + "]\nip = \"127.0.0.1\"\nport = " + strconv.Itoa(ports[key]) + "\n"
		}
		return text
	}
	startKeys := []string{"0"}
	if strings.HasPrefix(mode, "control-server-") {
		// listener.1 keeps its address in the reload, so the control server
		// sees no listener with a new address and no change of service.
		startKeys = []string{"0", "1"}
	}
	fileText := configText("1")
	if mode == "control-server-accepted" {
		fileText = configText("0", "1")
	}
	cfg = parseTestConfig(t, configText(startKeys...))
	configPath = filepath.Join(dir, "ctrld.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(fileText), 0o600))

	socketDir, err := os.MkdirTemp("", "ctrld709")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	cs, err := newControlServer(filepath.Join(socketDir, "s"))
	require.NoError(t, err)
	p := &prog{
		cfg: &cfg, cs: cs, waitCh: make(chan struct{}), stopCh: make(chan struct{}), runAbortCh: make(chan struct{}),
		runDone: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}), apiReloadCh: make(chan *ctrld.Config),
		reloadCh:         make(chan struct{}),
		reloadDoneCh:     make(chan reloadDone, 1),
		apiForceReloadCh: make(chan struct{}),
	}
	p.logger.Store(mainLog.Load())
	if mode == "api-reload" {
		p.startedInAPIMaintenance.Store(true)
	}
	close(p.waitCh)
	require.NoError(t, p.Start(nil))
	require.Eventually(t, func() bool { return postCalls.Load() == 1 }, 3*time.Second, time.Millisecond)

	apiReloadText := func(text string) reloadDone {
		t.Helper()
		reloadCfg := parseTestConfig(t, text)
		p.apiReloadCh <- &reloadCfg
		select {
		case done := <-p.reloadDoneCh:
			return done
		case <-time.After(5 * time.Second):
			t.Fatal("the reload did not finish")
			return reloadDone{}
		}
	}
	controlServerReload := func() int {
		t.Helper()
		w := httptest.NewRecorder()
		p.cs.mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, reloadPath, nil))
		return w.Code
	}

	switch mode {
	case "api-reload":
		// A different upstream address shows if the refused config reached
		// the upstream setup.
		ptrNameservers := p.ptrNameservers
		refusedText := strings.Replace(configText("1"), `endpoint = "127.0.0.1"`, `endpoint = "127.0.0.2"`, 1)
		require.True(t, apiReloadText(refusedText).restartNeeded, "the reload dropped a running listener, so only a restart can apply it")
		require.Equal(t, ptrNameservers, p.ptrNameservers, "a refused config must not set up its upstreams")
		written, err := os.ReadFile(configPath)
		require.NoError(t, err)
		require.Equal(t, fileText, string(written), "a refused config must not be written to disk")
		require.False(t, p.startedInAPIMaintenance.Load(), "a refused config must end the fast retry of a maintenance start")
	case "control-server-reload":
		require.Equal(t, http.StatusCreated, controlServerReload(), "the reload dropped a running listener, so only a restart can apply it")
	case "control-server-accepted":
		require.Equal(t, http.StatusOK, controlServerReload())
	case "unserved-listener-dropped":
		// listener.1 gets no DNS server, so a reload may drop it again.
		require.False(t, apiReloadText(configText("0", "1")).restartNeeded)
		require.False(t, apiReloadText(configText("0")).restartNeeded)
	case "no-listener-config":
		// The handler reads the map after it takes the semaphore, so holding
		// the only slot orders this change before that read.
		semaphore.acquire()
		p.mu.Lock()
		delete(p.cfg.Listener, "0")
		p.mu.Unlock()
		semaphore.release()
	}

	answer := queryListener(t, ports["0"])
	switch mode {
	case "no-listener-config":
		require.Equal(t, dns.RcodeServerFailure, answer.Rcode)
		// The line goes through the query sampler, so a listener that keeps
		// getting queries cannot flood the log file at error level.
		for range querySampleLimit {
			require.Equal(t, dns.RcodeServerFailure, queryListener(t, ports["0"]).Rcode)
		}
		require.Equal(t, querySampleLimit, countErrorLines(readRunLog(t, dir), "No config for [listener.0]"))
		p.health.mu.Lock()
		failedQueries := p.health.failedQueries
		p.health.mu.Unlock()
		require.EqualValues(t, querySampleLimit+1, failedQueries, "each SERVFAIL is a failed query for the query health grade")
	case "api-reload", "control-server-reload":
		require.Equal(t, dns.RcodeSuccess, answer.Rcode, "the refused reload must keep the running listener config")
		require.Equal(t, 1, countErrorLines(readRunLog(t, dir), "Reload refused: the new config has no [listener.0]"))
	default:
		require.Equal(t, dns.RcodeSuccess, answer.Rcode)
		require.NotContains(t, readRunLog(t, dir), "Reload refused")
	}

	close(p.stopCh)
	finished := make(chan struct{})
	go func() { p.finishRun(); close(finished) }()
	awaitShutdown(t, p.runDone)
	awaitShutdown(t, finished)
}

// Only a listener with a DNS server counts. A reload can add a listener that
// gets no DNS server, and a later reload may drop it again.
func TestDroppedListeners(t *testing.T) {
	newCfg := &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"1": {}}}
	require.Empty(t, droppedListeners([]string{"1"}, newCfg))
	require.Equal(t, []string{"[listener.0]", "[listener.2]"}, droppedListeners([]string{"0", "1", "2"}, newCfg))
}

// readRunLog returns the log_path file of the run. The run replaces mainLog
// with its own console and file cores, so the shared logOutput of the test
// binary does not see its lines.
func readRunLog(t *testing.T, dir string) string {
	t.Helper()
	runLog, err := os.ReadFile(filepath.Join(dir, "ctrld.log"))
	require.NoError(t, err)
	return string(runLog)
}

// countErrorLines counts the log_path lines at error level that hold text.
// The file uses the console encoder, so the level is a tab-separated field.
func countErrorLines(logText, text string) int {
	count := 0
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "\tERROR\t") && strings.Contains(line, text) {
			count++
		}
	}
	return count
}

// parseTestConfig reads a config the way a reload reads the config file.
func parseTestConfig(t *testing.T, text string) ctrld.Config {
	t.Helper()
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "ctrld")
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(text)))
	var parsed ctrld.Config
	require.NoError(t, v.Unmarshal(&parsed))
	return parsed
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func queryListener(t *testing.T, port int) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(selfCheckInternalTestDomain+".", dns.TypeA)
	answer, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	return answer
}

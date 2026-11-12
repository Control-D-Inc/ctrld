package cli

import (
	"context"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// On mobile in Control D mode, a start serves only the first listener of the
// config, at a fixed address. A reload gives the same result: the running DNS
// server keeps its address and serves the first listener of the new config,
// with the settings and the default upstream of that listener. Each case runs
// in a subprocess, because the run sets package globals.
func TestMobileReloadServesTheFirstListener(t *testing.T) {
	const env = "CTRLD_TEST_MOBILE_RELOAD"
	mode := os.Getenv(env)
	if mode == "" {
		for _, mode := range []string{"api-config", "api-refetch", "api-refetch-default-file"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMobileReloadServesTheFirstListener$", "-test.v")
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
	cdUID = "uid715"
	iface = ""
	monitorNetworkChangesFn = func(*prog) error { return nil }
	var postCalls atomic.Int32
	postRunFn = func(*prog) { postCalls.Add(1) }

	dir := t.TempDir()
	managedConfigMarkerPath = func() string { return filepath.Join(dir, managedConfigMarkerFile) }
	provisionResultPath = func() string { return filepath.Join(dir, provisionResultFileName) }
	// Each key has its own upstream, so the answer shows the default upstream
	// of the listener that the DNS server serves.
	answers := map[string]string{"0": "192.0.2.10", "1": "192.0.2.11"}
	upstreams := map[string]string{"0": answerWith(t, answers["0"]), "1": answerWith(t, answers["1"])}
	runningPort := freeLocalPort(t)
	configText := func(key string, port int) string {
		// A TOML literal string, because a Windows path has backslashes.
		return "[service]\nlog_path = '" + filepath.Join(dir, "ctrld.log") + "'\n" +
			"[network.0]\ncidrs = [\"127.0.0.0/8\"]\n" +
			"[upstream." + key + "]\ntype = \"legacy\"\nendpoint = \"" + upstreams[key] + "\"\n" +
			"[listener." + key + "]\nip = \"127.0.0.1\"\nport = " + strconv.Itoa(port) + "\n" +
			"[listener." + key + ".policy]\nname = \"policy of listener." + key + "\"\nfailover_rcodes = [\"SERVFAIL\"]\n"
	}
	startKey, newKey := "0", "1"
	if mode != "api-config" {
		startKey, newKey = "1", "0"
	}
	// The new config names another port, as a custom config of the resolver
	// can. The address of a mobile listener is fixed, so the reload keeps the
	// running one.
	newText := configText(newKey, freeLocalPort(t))
	cfg = parseTestConfig(t, configText(startKey, runningPort))
	configFile := filepath.Join(dir, "ctrld.toml")
	require.NoError(t, os.WriteFile(configFile, []byte(configText(startKey, runningPort)), 0o600))
	configPath = configFile
	if mode == "api-refetch-default-file" {
		// A start that found no config file wrote the default one. The apps
		// set no config path, and viper names no file then.
		configPath = ""
		defaultConfigFile = configFile
	}

	p := &prog{
		cfg: &cfg, waitCh: make(chan struct{}), stopCh: make(chan struct{}), runAbortCh: make(chan struct{}),
		runDone: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}), apiReloadCh: make(chan *ctrld.Config),
		reloadCh:         make(chan struct{}),
		reloadDoneCh:     make(chan reloadDone, 1),
		apiForceReloadCh: make(chan struct{}),
	}
	close(p.waitCh)
	require.NoError(t, p.Start(nil))
	require.Eventually(t, func() bool { return postCalls.Load() == 1 }, 3*time.Second, time.Millisecond)

	reload := func(apiCfg *ctrld.Config) reloadDone {
		t.Helper()
		p.apiReloadCh <- apiCfg
		select {
		case done := <-p.reloadDoneCh:
			return done
		case <-time.After(5 * time.Second):
			t.Fatal("the reload did not finish")
			return reloadDone{}
		}
	}
	requireServes := func(key string) {
		t.Helper()
		p.mu.Lock()
		running := maps.Clone(p.cfg.Listener)
		servedAs := maps.Clone(p.servedAs)
		// The handler reads the failover rcodes without a lock, so the config
		// must have them when the reload publishes it.
		var failoverRcodes []int
		if lc := running[key]; lc != nil && lc.Policy != nil {
			failoverRcodes = slices.Clone(lc.Policy.FailoverRcodeNumbers)
		}
		p.mu.Unlock()
		require.Equal(t, map[string]string{startKey: key}, servedAs)
		require.Len(t, running, 1)
		require.NotNil(t, running[key])
		require.Equal(t, "127.0.0.1", running[key].IP)
		require.Equal(t, runningPort, running[key].Port, "the reload must keep the address of the running listener")
		require.Equal(t, "policy of listener."+key, running[key].Policy.Name)
		require.Equal(t, []int{dns.RcodeServerFailure}, failoverRcodes)
		require.Equal(t, answers[key], answerOfListener(t, runningPort), "the query must go to the default upstream of [listener.%s]", key)
	}

	require.Equal(t, answers[startKey], answerOfListener(t, runningPort))
	switch mode {
	case "api-config":
		newCfg := parseTestConfig(t, newText)
		require.False(t, reload(&newCfg).restartNeeded)
		requireServes(newKey)
		require.Contains(t, logOutput.String(), "reload: the DNS server of [listener.0] serves [listener.1] of the new config from now on")
		// The next reload starts from the config of the other key.
		startCfg := parseTestConfig(t, configText(startKey, runningPort))
		require.False(t, reload(&startCfg).restartNeeded)
		requireServes(startKey)
	case "api-refetch", "api-refetch-default-file":
		// A change of the excludes or of the Internal Domains sends no config,
		// and the reload reads the file and fetches the config again.
		processCDFlagsRuntimeFn = func(_ context.Context, fetched *ctrld.Config) (*controld.ResolverConfig, error) {
			*fetched = parseTestConfig(t, newText)
			return &controld.ResolverConfig{}, nil
		}
		require.False(t, reload(nil).restartNeeded)
		requireServes(newKey)
	}
	require.NotContains(t, logOutput.String(), "reload refused")

	close(p.stopCh)
	finished := make(chan struct{})
	go func() { p.finishRun(); close(finished) }()
	awaitShutdown(t, p.runDone)
	awaitShutdown(t, finished)
}

// answerWith starts a DNS server that answers each A query with ip, and
// returns its address.
func answerWith(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(m)
		if rr, err := dns.NewRR(m.Question[0].Name + " 60 IN A " + ip); err == nil {
			answer.Answer = append(answer.Answer, rr)
		}
		_ = w.WriteMsg(answer)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// answerOfListener sends a query for a name that only a fake upstream
// answers, and returns the address in the answer.
func answerOfListener(t *testing.T, port int) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("mobile-reload.test.", dns.TypeA)
	answer, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	require.Len(t, answer.Answer, 1, "rcode %s", dns.RcodeToString[answer.Rcode])
	a, ok := answer.Answer[0].(*dns.A)
	require.True(t, ok)
	return a.A.String()
}

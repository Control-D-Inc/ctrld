package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

func TestStopRestorationFailureStillStopsWorkers(t *testing.T) {
	old := deAllocateIPFn
	t.Cleanup(func() { deAllocateIPFn = old })
	want := errors.New("deallocation failed")
	calls := 0
	deAllocateIPFn = func(string) error { calls++; return want }
	p := &prog{
		cfg:    &ctrld.Config{Service: ctrld.ServiceConfig{AllocateIP: true}, Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1"}}},
		waitCh: make(chan struct{}), stopCh: make(chan struct{}), runDone: make(chan struct{}),
		runAbortCh: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}),
		pinCodeValidCh: make(chan struct{}, 1),
	}
	p.logger.Store(mainLog.Load())
	// Accept the stop even if another test configured a deactivation pin.
	p.pinCodeValidCh <- struct{}{}
	require.NoError(t, p.Start(nil))
	require.ErrorIs(t, p.Stop(nil), want)
	require.True(t, stopRequested(p.stopCh))
	awaitShutdown(t, p.runDone)
	p.finishRun()
	require.ErrorIs(t, p.restoreOSState(), want, "the first error must survive sync.Once")
	require.Equal(t, 1, calls, "never invoke the real IP deallocator")
}

func awaitShutdown(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not complete")
	}
}

func TestFinishRunWaitsBeyondTimeout(t *testing.T) {
	c, peer := net.Pipe()
	defer peer.Close()
	p := &prog{cfg: &ctrld.Config{}, runAbortCh: make(chan struct{}), runDone: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}), logConn: c}
	p.logger.Store(mainLog.Load())
	done := make(chan struct{})
	go func() { p.finishRun(); close(done) }()
	select {
	case <-done:
		t.Fatal("released resources while the run was alive")
	case <-time.After(shutdownTimeout + 50*time.Millisecond):
	}
	close(p.runDone)
	awaitShutdown(t, done)
	_, err := peer.Write([]byte("x"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

// Each case runs in a subprocess because run initializes package-global config
// and logging. No service, interface DNS or network-monitor setup is permitted.
func TestRunListenerShutdown(t *testing.T) {
	const env = "CTRLD_TEST_LISTENER_SHUTDOWN"
	mode := os.Getenv(env)
	if mode == "" {
		for _, mode := range []string{"stop-before-ready", "abort-before-ready", "drain", "reload", "reload-before-ready", "stop-during-hook", "stop-during-post", "wire-udp", "wire-tcp", "api-drain"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunListenerShutdown$", "-test.v")
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
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Log(string(buf[:n]))
		}
	}()
	isMobile = func() bool { return true }
	cdUID = ""
	iface = ""
	apiEntered, apiCanceled, apiRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	if mode == "api-drain" {
		cdUID = "testuid"
		fetchResolverConfigFn = func(ctx context.Context, _ *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
			close(apiEntered)
			<-ctx.Done()
			close(apiCanceled)
			<-apiRelease
			return nil, ctx.Err()
		}
	}
	var monitorCalls, postCalls atomic.Int32
	monitorNetworkChangesFn = func(*prog, context.Context) error { monitorCalls.Add(1); return nil }
	postRunFn = func(*prog) { postCalls.Add(1) }
	dir := t.TempDir()
	cfg = ctrld.Config{Service: ctrld.ServiceConfig{LogPath: dir + "/ctrld.log"}, Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1"}}}
	p := &prog{
		cfg: &cfg, waitCh: make(chan struct{}), stopCh: make(chan struct{}), runAbortCh: make(chan struct{}),
		runDone: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}), apiReloadCh: make(chan *ctrld.Config),
		reloadDoneCh:     make(chan struct{}, 1),
		apiForceReloadCh: make(chan struct{}),
	}
	p.logger.Store(mainLog.Load())
	logConnection := &closeCountingLogConn{}
	p.logConn = logConnection
	entered, drain, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var hooks atomic.Int32
	p.onStarted = []func(){func() { hooks.Add(1) }}
	mutationEntered, mutationRelease, restored := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stopDuringMutation := mode == "stop-during-hook" || mode == "stop-during-post"
	if stopDuringMutation {
		mutation := func() {
			close(mutationEntered)
			<-mutationRelease
			select {
			case <-restored:
				t.Error("startup mutation ran after restoration")
			default:
			}
		}
		p.onStopped = []func(){func() { close(restored) }}
		if mode == "stop-during-hook" {
			p.onStarted = []func(){mutation}
		} else {
			postRunFn = func(*prog) { mutation(); postCalls.Add(1) }
		}
	}
	wire := mode == "wire-udp" || mode == "wire-tcp"
	if wire {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		cfg.Listener["0"].Port = ln.Addr().(*net.TCPAddr).Port
		require.NoError(t, ln.Close())
		// The real handler blocks in its semaphore while both server Shutdown
		// calls drain. Use an internal query so no external upstream is needed.
		serveDNSFn = func(p *prog, ctx context.Context, n string) error {
			p.sema = &shutdownSemaphore{entered: entered, resume: release}
			return p.serveDNS(ctx, n)
		}
	} else {
		serveDNSFn = func(p *prog, _ context.Context, _ string) error {
			close(entered)
			if mode == "drain" || mode == "reload" || mode == "api-drain" || stopDuringMutation {
				p.started <- struct{}{}
			}
			select {
			case <-p.stopCh:
			case <-p.runAbortCh:
			}
			close(drain)
			<-release
			return nil
		}
	}
	close(p.waitCh)
	require.NoError(t, p.Start(nil))
	var queryDone chan error
	if wire {
		require.Eventually(t, func() bool { return postCalls.Load() == 1 }, time.Second, time.Millisecond)
		proto := mode[len("wire-"):]
		queryDone = make(chan error, 1)
		go func() {
			m := new(dns.Msg)
			m.SetQuestion(selfCheckInternalTestDomain+".", dns.TypeA)
			answer, _, err := (&dns.Client{Net: proto, Timeout: 5 * time.Second}).Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Listener["0"].Port)))
			if err == nil && answer.Rcode != dns.RcodeSuccess {
				err = errors.New("internal query failed")
			}
			queryDone <- err
		}()
	}
	awaitShutdown(t, entered)
	if mode == "api-drain" {
		select {
		case p.apiForceReloadCh <- struct{}{}:
		case <-time.After(time.Second):
			t.Fatal("production run did not start the API reload worker")
		}
		awaitShutdown(t, apiEntered)
	}
	if mode == "reload" || mode == "reload-before-ready" {
		if mode == "reload" {
			require.Eventually(t, func() bool { return postCalls.Load() == 1 }, time.Second, time.Millisecond)
		}
		configPath = dir + "/reload.toml"
		p.apiReloadCh <- &ctrld.Config{
			Service:  cfg.Service,
			Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}},
			Network:  map[string]*ctrld.NetworkConfig{"0": {Cidrs: []string{"127.0.0.0/8"}}},
			Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: ctrld.ResolverTypeDOT, Endpoint: "example.test:853", BootstrapIP: "127.0.0.1"}},
		}
		if mode == "reload-before-ready" {
			// Give the reload a chance to reach the old run's cancellation path.
			select {
			case <-p.reloadDoneCh:
				t.Fatal("reload skipped one-time startup")
			case <-time.After(30 * time.Millisecond):
			}
			p.started <- struct{}{}
		}
		select {
		case <-p.reloadDoneCh:
		case <-time.After(3 * time.Second):
			t.Fatal("reload waited for a persistent listener to stop")
		}
		select {
		case <-drain:
			t.Fatal("reload stopped the persistent listener")
		default:
		}
		require.EqualValues(t, 1, hooks.Load())
		require.EqualValues(t, 1, postCalls.Load())
	}
	if stopDuringMutation {
		awaitShutdown(t, mutationEntered)
		stopDone := make(chan struct{})
		go func() { _ = p.Stop(nil); close(stopDone) }()
		select {
		case <-restored:
			t.Fatal("restoration raced a startup OS mutation")
		case <-time.After(30 * time.Millisecond):
		}
		close(mutationRelease)
		awaitShutdown(t, stopDone)
		awaitShutdown(t, restored)
		require.False(t, p.startOSState(func() { t.Error("startup permitted after restoration") }))
	} else if mode != "abort-before-ready" {
		close(p.stopCh)
	}
	finished := make(chan struct{})
	go func() { p.finishRun(); close(finished) }()
	awaitShutdown(t, p.runDone)
	if !wire {
		awaitShutdown(t, drain)
	}
	select {
	case <-finished:
		t.Fatal("finishRun returned before the listener/handler drained")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	if mode == "api-drain" {
		awaitShutdown(t, apiCanceled)
		select {
		case <-finished:
			t.Fatal("finishRun returned before the API reload worker")
		case <-time.After(30 * time.Millisecond):
		}
		close(apiRelease)
	}
	awaitShutdown(t, finished)
	require.EqualValues(t, 1, logConnection.closes.Load(), "startup and shutdown must share log-connection ownership")
	if wire {
		require.NoError(t, <-queryDone, "active DNS query must finish before resource retirement")
	}
	if mode == "stop-before-ready" || mode == "abort-before-ready" {
		require.Zero(t, hooks.Load(), "startup hooks must not run after cancellation")
		require.Zero(t, postCalls.Load())
	}
	require.EqualValues(t, 1, monitorCalls.Load(), "real network monitor must not be reached")
}

type shutdownSemaphore struct {
	entered chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (s *shutdownSemaphore) acquire() { s.once.Do(func() { close(s.entered) }); <-s.resume }
func (*shutdownSemaphore) release()   {}

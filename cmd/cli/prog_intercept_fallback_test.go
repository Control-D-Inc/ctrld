package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// TestInterfaceDNSFallbackViable covers when the interface-DNS fallback may be used
// after DNS intercept fails to start.
//
// The fallback names a resolver by IP with no port, so it can only reach a listener on
// :53. Taking it with the listener on a redirect-dependent port produced a total DNS
// outage on macOS: the interface points at 127.0.0.1, mDNSResponder answers there, and
// its upstream is ctrld's own address - a resolution loop with a healthy ctrld listener
// nothing can reach. Intercept startup refuses the fallback in that case rather than
// creating it.
func TestInterfaceDNSFallbackViable(t *testing.T) {
	tests := []struct {
		name string
		lc   *ctrld.ListenerConfig
		want bool
	}{
		{
			name: "listener on 53 can be reached by interface DNS",
			lc:   &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 53},
			want: true,
		},
		{
			// The reported outage: no local resolver, so the :5354 fallback port
			// cannot be expressed by interface DNS.
			name: "listener on the fallback port cannot",
			lc:   &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 5354},
			want: false,
		},
		{
			name: "any other non-53 port cannot",
			lc:   &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 5300},
			want: false,
		},

		{
			// Port is resolved elsewhere and defaults to 53; nothing to refuse yet.
			name: "unset port is not refused",
			lc:   &ctrld.ListenerConfig{IP: "127.0.0.1"},
			want: true,
		},
		{
			name: "no listener is not refused",
			lc:   nil,
			want: true,
		},
		{
			// A non-loopback listener on 53 is still reachable by IP.
			name: "non-loopback listener on 53",
			lc:   &ctrld.ListenerConfig{IP: "192.168.1.10", Port: 53},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := interfaceDNSFallbackViable(tc.lc); got != tc.want {
				t.Errorf("interfaceDNSFallbackViable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// interceptFallbackHarness drives setDNS() through the intercept-start failure path and
// records the side effects that decide whether the host ends up with a working
// resolver.
//
// Every host-touching step is stubbed, including the intercept start itself: this test
// runs untagged on Linux, macOS and Windows runners, where the real startDNSIntercept
// would set up pf or install an NRPT rule on the machine running the tests. Stubbing it
// also makes the precondition deterministic - the failure under test is injected rather
// than depending on the runner denying a privileged operation.
type interceptFallbackHarness struct {
	interceptCalls       int
	installedNameservers []string
	installCalls         int
	resetCalls           int
	refusals             []string
}

func newInterceptFallbackHarness(t *testing.T, lc *ctrld.ListenerConfig) *interceptFallbackHarness {
	t.Helper()
	h := &interceptFallbackHarness{}

	origStart, origInstall := startDNSInterceptFn, setDnsForRunningIfaceFn
	origReset, origFatal := resetDNSFn, refuseFallbackFatal
	origCfg, origMode, origIntercept, origHard := cfg, interceptMode, dnsIntercept, hardIntercept
	t.Cleanup(func() {
		startDNSInterceptFn, setDnsForRunningIfaceFn = origStart, origInstall
		resetDNSFn, refuseFallbackFatal = origReset, origFatal
		cfg, interceptMode, dnsIntercept, hardIntercept = origCfg, origMode, origIntercept, origHard
	})

	// Never reach the real interceptor: it would configure pf on macOS and NRPT on
	// Windows, on the machine running the tests.
	startDNSInterceptFn = func(_ *prog) error {
		h.interceptCalls++
		return errors.New("dns intercept: injected start failure")
	}
	setDnsForRunningIfaceFn = func(_ *prog, nameservers []string) *net.Interface {
		h.installCalls++
		h.installedNameservers = nameservers
		return nil
	}
	resetDNSFn = func(_ *prog, _ bool, _ bool) { h.resetCalls++ }
	refuseFallbackFatal = func(format string, v ...any) {
		h.refusals = append(h.refusals, fmt.Sprintf(format, v...))
	}

	cfg = ctrld.Config{}
	cfg.Service.InterceptMode = "dns"
	cfg.Listener = map[string]*ctrld.ListenerConfig{"0": lc}
	watchdogOff := false
	cfg.Service.DnsWatchdogEnabled = &watchdogOff
	interceptMode, dnsIntercept, hardIntercept = "dns", false, false
	return h
}

func (h *interceptFallbackHarness) run(t *testing.T) {
	t.Helper()
	p := &prog{cfg: &cfg}
	p.logger.Store(mainLog.Load())
	p.setDNS()
}

func TestSetDNSExplicitOffOverridesConfig(t *testing.T) {
	h := newInterceptFallbackHarness(t, &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 53})
	interceptMode = "off"
	dnsIntercept = false
	hardIntercept = false

	h.run(t)

	if h.interceptCalls != 0 {
		t.Fatalf("intercept start called %d time(s), want 0: explicit off must override service.intercept_mode", h.interceptCalls)
	}
	if h.installCalls != 1 {
		t.Fatalf("interface DNS installed %d time(s), want 1", h.installCalls)
	}
}

// TestSetDNSRefusesUnreachableFallback is the behaviour test for the reported outage: it
// drives the real setDNS() lifecycle rather than the classification helper alone.
//
// Deleting or bypassing the guard in setDNS makes the first case fail, because interface
// DNS then gets installed pointing at a listener that cannot answer on :53 - which is
// the resolution loop this refuses to create.
func TestSetDNSRefusesUnreachableFallback(t *testing.T) {
	t.Run("non-53 listener refuses the fallback and restores DNS", func(t *testing.T) {
		h := newInterceptFallbackHarness(t, &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 5354})
		h.run(t)

		if h.interceptCalls != 1 {
			t.Fatalf("intercept start called %d time(s) through the seam, want 1 — the real platform interceptor must never run here", h.interceptCalls)
		}
		if h.installCalls != 0 {
			t.Errorf("interface DNS was installed %d time(s) for a listener on :5354 — that is the resolver loop", h.installCalls)
		}
		if h.resetCalls == 0 {
			t.Error("host DNS was not restored before refusing, leaving the interface pointed at a ctrld that is not serving")
		}
		if len(h.refusals) == 0 {
			t.Fatal("refusal was not surfaced: startup must fail loudly rather than silently skip the fallback")
		}
		if !strings.Contains(h.refusals[0], "5354") {
			t.Errorf("refusal does not name the unreachable port: %q", h.refusals[0])
		}
	})

	t.Run("listener on 53 still reaches the interface-DNS fallback", func(t *testing.T) {
		h := newInterceptFallbackHarness(t, &ctrld.ListenerConfig{IP: "127.0.0.1", Port: 53})
		h.run(t)

		if h.interceptCalls != 1 {
			t.Fatalf("intercept start called %d time(s) through the seam, want 1", h.interceptCalls)
		}
		if h.installCalls != 1 {
			t.Errorf("interface DNS installed %d time(s), want 1: a listener on :53 is reachable, so the fallback must still apply", h.installCalls)
		}
		if len(h.refusals) != 0 {
			t.Errorf("unexpected refusal for a reachable listener: %v", h.refusals)
		}
		if len(h.installedNameservers) == 0 {
			t.Error("fallback installed no nameservers")
		}
	})
}

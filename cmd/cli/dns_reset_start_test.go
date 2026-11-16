package cli

import (
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// startResetHost is a fake host for the start-time DNS reset: the static DNS of
// each adapter, which adapters the running-interface lookup and the physical
// enumeration see, and which adapters were reset to DHCP.
type startResetHost struct {
	mu        sync.Mutex
	static    map[string][]string
	readErr   map[string]error
	reset     []string
	fullReset int
	// fullResetRestoreStatic is the restoreStatic argument of the last
	// blanket reset.
	fullResetRestoreStatic bool
	// forwarderCleanups counts the domain controller forwarder cleanup.
	forwarderCleanups int
}

func (h *startResetHost) resets() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.reset)
}

// stubStartResetHost wires every host-touching boundary of resetDNSAtStart to
// h. running is the default-route adapter (a VPN adapter in the field case) and
// physical lists the adapters withEachPhysicalInterfaces visits.
func stubStartResetHost(t *testing.T, mode string, running string, physical ...string) *startResetHost {
	t.Helper()
	h := &startResetHost{static: map[string][]string{}, readErr: map[string]error{}}

	ifaces := map[string]*net.Interface{}
	idx := 1
	for _, name := range append([]string{running}, physical...) {
		ifaces[name] = &net.Interface{Index: idx, Name: name, HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, byte(idx)}, Flags: net.FlagUp}
		idx++
	}

	oldNetIface, oldStatic := netInterfaceFn, currentStaticDNSFn
	oldSet, oldReset, oldNM := setIfaceDNSFn, resetIfaceDNSFn, restoreNetworkManagerFn
	oldIgnore, oldFull, oldRemove := resetDnsIgnoreUnusableInterfaceFn, resetDNSFn, removeInterceptDNSTargetFn
	oldMode, oldWalk, oldFwd, oldGOOS := interceptMode, withEachPhysicalInterfacesFn, removeSavedDnsServerForwardersFn, startResetGOOS
	t.Cleanup(func() {
		startResetGOOS = oldGOOS
		withEachPhysicalInterfacesFn, removeSavedDnsServerForwardersFn = oldWalk, oldFwd
		netInterfaceFn, currentStaticDNSFn = oldNetIface, oldStatic
		setIfaceDNSFn, resetIfaceDNSFn, restoreNetworkManagerFn = oldSet, oldReset, oldNM
		resetDnsIgnoreUnusableInterfaceFn, resetDNSFn, removeInterceptDNSTargetFn = oldIgnore, oldFull, oldRemove
		interceptMode = oldMode
	})
	interceptMode = mode
	startResetGOOS = "windows"

	netInterfaceFn = func(name string) (*net.Interface, error) {
		if i, ok := ifaces[name]; ok && name == running {
			return i, nil
		}
		return nil, errInterfaceNotFound
	}
	// The real walk filters by the host's own adapter list; this one visits
	// the fake physical adapters, skipping the excluded running one, as the
	// real walk does.
	withEachPhysicalInterfacesFn = func(exclude, _ string, f func(*net.Interface) error) {
		for _, name := range physical {
			if name == exclude {
				continue
			}
			if err := f(ifaces[name]); err != nil {
				t.Errorf("reset of %s failed: %v", name, err)
			}
		}
	}
	currentStaticDNSFn = func(i *net.Interface) ([]string, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.readErr[i.Name]; err != nil {
			return nil, err
		}
		return slices.Clone(h.static[i.Name]), nil
	}
	record := func(i *net.Interface) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.reset = append(h.reset, i.Name)
		delete(h.static, i.Name)
		return nil
	}
	resetIfaceDNSFn = record
	resetDnsIgnoreUnusableInterfaceFn = record
	setIfaceDNSFn = func(i *net.Interface, ns []string) error {
		t.Errorf("start reset set DNS %v on %s: intercept mode must never write adapter DNS", ns, i.Name)
		return nil
	}
	restoreNetworkManagerFn = func() error { return nil }
	removeInterceptDNSTargetFn = func(*prog, string) {}
	removeSavedDnsServerForwardersFn = func() {
		h.mu.Lock()
		h.forwarderCleanups++
		h.mu.Unlock()
	}
	resetDNSFn = func(p *prog, isStart, restoreStatic bool) {
		h.mu.Lock()
		h.fullReset++
		h.fullResetRestoreStatic = restoreStatic
		h.mu.Unlock()
	}
	return h
}

func newStartResetProg(running string) *prog {
	return &prog{cfg: &ctrld.Config{}, runningIface: running, requiredMultiNICsConfig: true}
}

// TestResetDNSAtStartInterceptKeepsForeignDNS is the field case: Windows, "dns"
// intercept mode, the default route on a Cisco AnyConnect adapter whose DNS the
// VPN client pushed. Before this change the start reset cleared it to DHCP, the
// adapter fell back to Windows' fec0:0:0:ffff::1-3, and every OS-resolver
// lookup for the VPN's domain waited 3x2 s on dead servers, then got NXDOMAIN
// from the LAN router. Static DNS an administrator set on Wi-Fi was cleared on
// every start too.
func TestResetDNSAtStartInterceptKeepsForeignDNS(t *testing.T) {
	for _, mode := range []string{"dns", "hard"} {
		t.Run(mode, func(t *testing.T) {
			h := stubStartResetHost(t, mode, "Ethernet 2", "Wi-Fi", "Ethernet")
			h.static["Ethernet 2"] = []string{"10.131.18.144"}
			h.static["Wi-Fi"] = []string{"192.0.2.53", "2001:db8::53"}

			newStartResetProg("Ethernet 2").resetDNSAtStart()

			if got := h.resets(); len(got) != 0 {
				t.Errorf("reset adapters %v, want none: no adapter carries ctrld's listener", got)
			}
			if h.fullReset != 0 {
				t.Error("intercept mode ran the blanket interface-DNS reset")
			}
			if h.forwarderCleanups != 1 {
				t.Errorf("domain controller forwarder cleanup ran %d times, want 1 even with no adapter reset", h.forwarderCleanups)
			}
			if got := h.static["Ethernet 2"]; !slices.Equal(got, []string{"10.131.18.144"}) {
				t.Errorf("VPN adapter DNS = %v, want the pushed resolver kept", got)
			}
			if got := h.static["Wi-Fi"]; len(got) != 2 {
				t.Errorf("Wi-Fi static DNS = %v, want the administrator's servers kept", got)
			}
		})
	}
}

// TestResetDNSAtStartInterceptClearsLeftoverListener covers the cleanup the
// start reset exists for: an earlier interface-DNS-mode run (an off -> dns
// switch, an upgrade across the platform default change, or a crash) left the
// listener on adapters. Those, and only those, must go back to DHCP.
func TestResetDNSAtStartInterceptClearsLeftoverListener(t *testing.T) {
	h := stubStartResetHost(t, "dns", "Wi-Fi", "Ethernet", "Ethernet 3")
	h.static["Wi-Fi"] = []string{"127.0.0.1"}
	h.static["Ethernet"] = []string{"::1", "127.0.0.1"}
	h.static["Ethernet 3"] = []string{"192.0.2.53"}

	newStartResetProg("Wi-Fi").resetDNSAtStart()

	got := h.resets()
	slices.Sort(got)
	if want := []string{"Ethernet", "Wi-Fi"}; !slices.Equal(got, want) {
		t.Errorf("reset adapters %v, want %v", got, want)
	}
	if _, ok := h.static["Ethernet 3"]; !ok {
		t.Error("an adapter with non-loopback static DNS was reset")
	}
}

// TestResetDNSAtStartInterceptMixedListenerIsOurs: a loopback entry next to a
// real server is still ctrld's leftover (setDNS writes the listener plus the
// IPv6 loopback), so the adapter is reset as before.
func TestResetDNSAtStartInterceptMixedListenerIsOurs(t *testing.T) {
	h := stubStartResetHost(t, "dns", "Wi-Fi")
	h.static["Wi-Fi"] = []string{"127.0.0.1", "192.0.2.53"}

	newStartResetProg("Wi-Fi").resetDNSAtStart()

	if got := h.resets(); !slices.Equal(got, []string{"Wi-Fi"}) {
		t.Errorf("reset adapters %v, want [Wi-Fi]", got)
	}
}

// TestResetDNSAtStartInterceptUnreadableDNSResets: when the adapter's DNS
// cannot be read, a leftover listener cannot be ruled out, so the reset that
// every start ran before is kept for that adapter.
func TestResetDNSAtStartInterceptUnreadableDNSResets(t *testing.T) {
	h := stubStartResetHost(t, "dns", "Ethernet 2", "Wi-Fi")
	h.readErr["Ethernet 2"] = errors.New("registry: access denied")
	h.static["Wi-Fi"] = []string{"192.0.2.53"}

	newStartResetProg("Ethernet 2").resetDNSAtStart()

	if got := h.resets(); !slices.Equal(got, []string{"Ethernet 2"}) {
		t.Errorf("reset adapters %v, want only the unreadable one", got)
	}
}

// TestResetDNSAtStartInterfaceModeUnchanged: interface DNS mode keeps the
// blanket reset, because setDNS overwrites the adapters right after it.
func TestResetDNSAtStartInterfaceModeUnchanged(t *testing.T) {
	h := stubStartResetHost(t, "off", "Ethernet 2", "Wi-Fi")
	h.static["Ethernet 2"] = []string{"10.131.18.144"}

	newStartResetProg("Ethernet 2").resetDNSAtStart()

	if h.fullReset != 1 {
		t.Errorf("blanket reset ran %d times, want 1", h.fullReset)
	}
	if got := h.resets(); len(got) != 0 {
		t.Errorf("selective reset touched %v in interface DNS mode", got)
	}
}

// TestResetDNSAtStartInterceptLogsDecision: support must be able to see from a
// log send which adapters were reset and why, without static DNS values of
// adapters ctrld left alone.
func TestResetDNSAtStartInterceptLogsDecision(t *testing.T) {
	buf := captureDNSResetLogs(t)
	h := stubStartResetHost(t, "dns", "Ethernet 2", "Wi-Fi")
	h.static["Ethernet 2"] = []string{"10.131.18.144"}
	h.static["Wi-Fi"] = []string{"127.0.0.1"}

	newStartResetProg("Ethernet 2").resetDNSAtStart()

	kept := findLogEntry(t, buf.String(), "leaving it unchanged in intercept mode")
	if kept["iface"] != "Ethernet 2" {
		t.Errorf("kept iface = %v, want Ethernet 2", kept["iface"])
	}
	if strings.Contains(buf.String(), "10.131.18.144") {
		t.Error("log names the static DNS of an adapter ctrld did not touch")
	}
	leftover := findLogEntry(t, buf.String(), "loopback listener left by an earlier run")
	if leftover["iface"] != "Wi-Fi" || leftover["level"] != "info" {
		t.Errorf("leftover entry = %v, want info for Wi-Fi", leftover)
	}
}

// TestPostRunUsesStartReset pins the wiring: postRun reaches the start reset
// through resetDNSAtStart, not the blanket resetDNS.
func TestPostRunUsesStartReset(t *testing.T) {
	oldService, oldAtStart, oldFull, oldInit := runningAsService, resetDNSAtStartFn, resetDNSFn, initializeOsResolverWithSystemNameserversFn
	oldMode, oldSource, oldIntercept, oldRemove := interceptMode, interceptModeSource, dnsIntercept, removeInterceptDNSTargetFn
	t.Cleanup(func() {
		runningAsService, resetDNSAtStartFn, resetDNSFn, initializeOsResolverWithSystemNameserversFn = oldService, oldAtStart, oldFull, oldInit
		interceptMode, interceptModeSource, dnsIntercept, removeInterceptDNSTargetFn = oldMode, oldSource, oldIntercept, oldRemove
	})
	runningAsService = func() bool { return true }
	calls := 0
	resetDNSAtStartFn = func(*prog) { calls++ }
	resetDNSFn = func(*prog, bool, bool) { t.Error("postRun called the blanket resetDNS directly") }
	initializeOsResolverWithSystemNameserversFn = func(bool, string) ([]string, []string) { return nil, nil }
	removeInterceptDNSTargetFn = func(*prog, string) {}
	// Interface DNS mode with no listener: setDNS returns before touching the
	// host, so only the reset wiring is exercised.
	interceptMode, interceptModeSource, dnsIntercept = "off", "", false

	p := &prog{cfg: &ctrld.Config{}, csSetDnsDone: make(chan struct{}, 1)}
	p.postRun()

	if calls != 1 {
		t.Errorf("resetDNSAtStart called %d times, want 1", calls)
	}
}

// TestInterceptModeKeepsAdapterDNS: only Windows and macOS implement intercept
// mode. Elsewhere a configured intercept mode falls back to interface DNS mode,
// which still needs the blanket reset.
func TestInterceptModeKeepsAdapterDNS(t *testing.T) {
	for _, tc := range []struct {
		goos, mode string
		want       bool
	}{
		{"windows", "dns", true},
		{"windows", "hard", true},
		{"darwin", "dns", true},
		{"darwin", "hard", true},
		{"windows", "off", false},
		{"windows", "", false},
		{"darwin", "off", false},
		{"linux", "dns", false},
		{"freebsd", "hard", false},
	} {
		if got := interceptModeKeepsAdapterDNS(tc.goos, tc.mode); got != tc.want {
			t.Errorf("interceptModeKeepsAdapterDNS(%q, %q) = %v, want %v", tc.goos, tc.mode, got, tc.want)
		}
	}
}

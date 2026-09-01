//go:build darwin

package cli

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

type interceptTargetHarness struct {
	dns          map[string][]string
	saved        map[string][]string
	serviceByDev map[string]string
	dhcp         []string
	dhcpErr      error
	readErr      error
	setErr       error
	resetErr     error
	setCalls     []string
	resetCalls   []string
	statePath    string
}

func newInterceptTargetHarness(t *testing.T) *interceptTargetHarness {
	t.Helper()
	h := &interceptTargetHarness{
		dns:          make(map[string][]string),
		saved:        make(map[string][]string),
		serviceByDev: map[string]string{"en1": "Wi-Fi"},
		statePath:    filepath.Join(t.TempDir(), interceptDNSTargetStateFile),
	}

	origPath := interceptDNSTargetStatePathFn
	origRoute := interceptDefaultRouteInterfaceFn
	origIface := interceptInterfaceByNameFn
	origPatch := interceptPatchNetIfaceNameFn
	origCurrent := interceptCurrentStaticDNSFn
	origSave := interceptSaveCurrentStaticDNSFn
	origSet := interceptSetDNSFn
	origSaved := interceptSavedStaticNameserversFn
	origReset := interceptResetDNSIgnoreUnusableIfaceFn
	origDHCP := interceptDHCPNameserversForInterfaceFn
	origIntercept := dnsIntercept
	t.Cleanup(func() {
		interceptDNSTargetStatePathFn = origPath
		interceptDefaultRouteInterfaceFn = origRoute
		interceptInterfaceByNameFn = origIface
		interceptPatchNetIfaceNameFn = origPatch
		interceptCurrentStaticDNSFn = origCurrent
		interceptSaveCurrentStaticDNSFn = origSave
		interceptSetDNSFn = origSet
		interceptSavedStaticNameserversFn = origSaved
		interceptResetDNSIgnoreUnusableIfaceFn = origReset
		interceptDHCPNameserversForInterfaceFn = origDHCP
		dnsIntercept = origIntercept
	})

	dnsIntercept = true
	interceptDNSTargetStatePathFn = func() string { return h.statePath }
	interceptDefaultRouteInterfaceFn = func() (string, error) { return "en1", nil }
	interceptInterfaceByNameFn = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	interceptPatchNetIfaceNameFn = func(iface *net.Interface) (bool, error) {
		service, ok := h.serviceByDev[iface.Name]
		if !ok {
			return false, errors.New("unknown network service")
		}
		iface.Name = service
		return true, nil
	}
	interceptCurrentStaticDNSFn = func(iface *net.Interface) ([]string, error) {
		if h.readErr != nil {
			return nil, h.readErr
		}
		return slices.Clone(h.dns[iface.Name]), nil
	}
	interceptSaveCurrentStaticDNSFn = func(iface *net.Interface) error {
		h.saved[iface.Name] = slices.Clone(h.dns[iface.Name])
		return nil
	}
	interceptSetDNSFn = func(iface *net.Interface, nameservers []string) error {
		h.setCalls = append(h.setCalls, iface.Name)
		if h.setErr != nil {
			return h.setErr
		}
		h.dns[iface.Name] = slices.Clone(nameservers)
		return nil
	}
	interceptSavedStaticNameserversFn = func(iface *net.Interface) []string {
		return slices.Clone(h.saved[iface.Name])
	}
	interceptResetDNSIgnoreUnusableIfaceFn = func(iface *net.Interface) error {
		h.resetCalls = append(h.resetCalls, iface.Name)
		if h.resetErr != nil {
			return h.resetErr
		}
		h.dns[iface.Name] = nil
		return nil
	}
	interceptDHCPNameserversForInterfaceFn = func(iface string) ([]string, error) {
		if iface != "en1" {
			return nil, errors.New("DHCP lookup used a non-default interface")
		}
		return slices.Clone(h.dhcp), h.dhcpErr
	}
	return h
}

func newInterceptTargetProg() *prog {
	return &prog{
		cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{
			"0": {IP: "127.0.0.1", Port: 5354},
		}},
		dnsInterceptState: &interceptStateStub{},
	}
}

func persistInterceptTargetForTest(t *testing.T, p *prog, service, value string) {
	t.Helper()
	p.interceptDNSTargetMu.Lock()
	defer p.interceptDNSTargetMu.Unlock()
	p.interceptDNSTargetLoaded = true
	p.interceptDNSTargetService = service
	p.interceptDNSTargetSetValue = value
	p.persistInterceptDNSTargetStateLocked()
}

func TestEnsureInterceptDNSTargetRequiresCompletedDiscovery(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	p.ensureInterceptDNSTarget(nil)
	if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
		t.Fatal("nil system discovery changed service DNS")
	}
}

func TestEnsureInterceptDNSTargetMigratesService(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	persistInterceptTargetForTest(t, p, "iPhone USB", "127.0.0.53")
	h.dns["iPhone USB"] = []string{"127.0.0.53"}
	h.dns["Wi-Fi"] = nil

	p.ensureInterceptDNSTarget([]string{})

	if len(h.dns["iPhone USB"]) != 0 {
		t.Fatalf("old service DNS = %v, want empty", h.dns["iPhone USB"])
	}
	if got := h.dns["Wi-Fi"]; !slices.Equal(got, []string{"127.0.0.53"}) {
		t.Fatalf("new service DNS = %v, want [127.0.0.53]", got)
	}
	if p.interceptDNSTargetService != "Wi-Fi" || p.interceptDNSTargetSetValue != "127.0.0.53" {
		t.Fatalf("tracking = %q/%q, want Wi-Fi/127.0.0.53", p.interceptDNSTargetService, p.interceptDNSTargetSetValue)
	}
}

func TestEnsureInterceptDNSTargetUsesDefaultRouteDHCPOnly(t *testing.T) {
	t.Run("other interface IPv4 does not suppress target", func(t *testing.T) {
		h := newInterceptTargetHarness(t)
		p := newInterceptTargetProg()
		p.ensureInterceptDNSTarget([]string{"10.10.10.1"})
		if got := h.dns["Wi-Fi"]; !slices.Equal(got, []string{"127.0.0.53"}) {
			t.Fatalf("other interface DNS suppressed target: %v", got)
		}
	})

	t.Run("returned default route DHCP removes target", func(t *testing.T) {
		h := newInterceptTargetHarness(t)
		p := newInterceptTargetProg()
		persistInterceptTargetForTest(t, p, "Wi-Fi", "127.0.0.53")
		h.dns["Wi-Fi"] = []string{"127.0.0.53"}
		h.dhcp = []string{"192.168.10.1"}

		p.ensureInterceptDNSTarget([]string{"10.10.10.1"})

		if len(h.dns["Wi-Fi"]) != 0 || p.interceptDNSTargetService != "" {
			t.Fatalf("returned default-route DHCP DNS did not remove target: dns=%v service=%q", h.dns["Wi-Fi"], p.interceptDNSTargetService)
		}
	})
}

func TestRemoveInterceptDNSTargetRestoresStateFileAfterRestart(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.dns["iPhone USB"] = []string{"127.0.0.53"}
	if err := os.WriteFile(h.statePath, []byte(`{"service":"iPhone USB","value":"127.0.0.53"}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := newInterceptTargetProg()

	p.removeInterceptDNSTarget("intercept mode inactive")

	if len(h.dns["iPhone USB"]) != 0 || p.interceptDNSTargetService != "" {
		t.Fatalf("restart cleanup failed: dns=%v service=%q", h.dns["iPhone USB"], p.interceptDNSTargetService)
	}
	if _, err := os.Stat(h.statePath); !os.IsNotExist(err) {
		t.Fatalf("state file still exists after cleanup: %v", err)
	}
}

func TestRemoveInterceptDNSTargetKeepsExternalDNS(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	persistInterceptTargetForTest(t, p, "Wi-Fi", "127.0.0.53")
	h.dns["Wi-Fi"] = []string{"8.8.8.8"}

	p.removeInterceptDNSTarget("test")

	if !slices.Equal(h.dns["Wi-Fi"], []string{"8.8.8.8"}) || len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
		t.Fatalf("external DNS was changed: dns=%v set=%v reset=%v", h.dns["Wi-Fi"], h.setCalls, h.resetCalls)
	}
	if p.interceptDNSTargetService != "" {
		t.Fatal("external change left stale ownership tracking")
	}
}

func TestRemoveInterceptDNSTargetRetainsStateOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readErr  error
		resetErr error
	}{
		{"read failure", errors.New("networksetup read failed"), nil},
		{"restore failure", nil, errors.New("networksetup reset failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			persistInterceptTargetForTest(t, p, "Wi-Fi", "127.0.0.53")
			h.dns["Wi-Fi"] = []string{"127.0.0.53"}
			h.readErr = tc.readErr
			h.resetErr = tc.resetErr

			p.removeInterceptDNSTarget("test")

			if p.interceptDNSTargetService != "Wi-Fi" || p.interceptDNSTargetSetValue != "127.0.0.53" {
				t.Fatal("failed cleanup discarded retry state")
			}
			if _, err := os.Stat(h.statePath); err != nil {
				t.Fatalf("failed cleanup removed persisted retry state: %v", err)
			}
		})
	}
}

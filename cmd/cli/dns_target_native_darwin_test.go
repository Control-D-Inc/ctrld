//go:build darwin

package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNativeCLATTargetPreservesNonOwnedLoopback(t *testing.T) {
	for _, static := range [][]string{{"::1"}, {"::1", "2001:db8::53"}, {"127.0.0.1"}, {"127.0.0.1", "::1"}} {
		t.Run(strings.Join(static, ","), func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.nativeCLAT = true
			h.dhcpErr = errors.New("no DHCPv4")
			h.dns["Wi-Fi"] = slices.Clone(static)
			backup := filepath.Join(t.TempDir(), ".dns_Wi-Fi")
			interceptSaveStaticDNSSnapshotFn = func(_ *net.Interface, snapshot []string, owned string) error {
				return saveTargetStaticDNSSnapshot(backup, snapshot, owned)
			}
			p := newInterceptTargetProg()
			p.cfg.Listener["0"].Port = 53
			p.ensureInterceptDNSTarget([]string{})
			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 || p.interceptDNSTargetService != "" {
				t.Fatalf("local resolver overwritten: set=%v reset=%v owner=%q", h.setCalls, h.resetCalls, p.interceptDNSTargetService)
			}
			p.removeInterceptDNSTarget("shutdown")
			if !slices.Equal(h.dns["Wi-Fi"], static) {
				t.Fatalf("lost user DNS: got %v, want %v", h.dns["Wi-Fi"], static)
			}
			if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("backup unexpectedly changed: %v", err)
			}
		})
	}
}

func TestNativeCLATTargetRejectsLoopbackBeforeSnapshot(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no DHCPv4")
	h.dns["Wi-Fi"] = []string{"::1", "2001:db8::53"}
	h.dns["Old service"] = []string{"127.0.0.53"}
	interceptSaveStaticDNSSnapshotFn = func(*net.Interface, []string, string) error {
		t.Fatal("non-owned IPv6 loopback admitted to snapshot")
		return nil
	}
	p := newInterceptTargetProg()
	persistInterceptTargetForTest(t, p, "Old service", "127.0.0.53")
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || len(h.resetCalls) != 0 || p.interceptDNSTargetService != "Old service" {
		t.Fatal("rejected admission changed old ownership")
	}
}

func TestNativeCLATTargetLoopbackKeepsIPv4CleanupFirst(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no DHCPv4")
	h.dns["Wi-Fi"] = []string{"::1", "127.0.0.1"}
	h.dns["Old service"] = []string{"127.0.0.53"}
	p := newInterceptTargetProg()
	persistInterceptTargetForTest(t, p, "Old service", "127.0.0.53")
	p.ensureInterceptDNSTarget([]string{})
	if !slices.Equal(h.resetCalls, []string{"Old service"}) || len(h.setCalls) != 0 || p.interceptDNSTargetService != "" {
		t.Fatalf("IPv4 cleanup skipped: reset=%v set=%v owner=%q", h.resetCalls, h.setCalls, p.interceptDNSTargetService)
	}
	if !slices.Equal(h.dns["Wi-Fi"], []string{"::1", "127.0.0.1"}) {
		t.Fatal("external local resolvers changed")
	}
}

func TestNativeCLATTargetSnapshotRejectsNonOwnedLoopback(t *testing.T) {
	for _, snapshot := range [][]string{{"::1"}, {"2001:db8::53", "::1"}, {"127.0.0.1"}, {"127.0.0.53", "::1"}} {
		t.Run(strings.Join(snapshot, ","), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup")
			const original = "2001:db8::54"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if err := saveTargetStaticDNSSnapshot(path, snapshot, "127.0.0.53"); err == nil {
				t.Fatal("accepted unrestorable loopback snapshot")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != original {
				t.Fatalf("failed snapshot changed backup: %q %v", got, err)
			}
		})
	}
	for _, owned := range []string{"127.0.0.53", "::1", "10.0.0.53"} {
		t.Run("owned "+owned, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup")
			const original = "2001:db8::54"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if err := saveTargetStaticDNSSnapshot(path, []string{owned}, owned); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != original {
				t.Fatalf("owned target replaced backup: %q %v", got, err)
			}
		})
	}
}

func TestNativeCLATTargetFallback(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		clat                        bool
		nativeErr, readErr, saveErr error
		static, dhcp                []string
		want                        bool
	}{
		{name: "CLAT", clat: true, want: true},
		{name: "unknown"},
		{name: "native read error", clat: true, nativeErr: errors.New("read failed")},
		{name: "static read error", clat: true, readErr: errors.New("read failed")},
		{name: "backup error", clat: true, saveErr: errors.New("disk full")},
		{name: "static IPv4", clat: true, static: []string{"9.9.9.9"}},
		{name: "partial DHCP IPv4", clat: true, dhcp: []string{"1.1.1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.dhcpErr = errors.New("getoption and getpacket exit 1")
			h.nativeCLAT, h.nativeErr, h.readErr, h.saveErr = tc.clat, tc.nativeErr, tc.readErr, tc.saveErr
			h.dns["Wi-Fi"], h.dhcp = tc.static, tc.dhcp
			p := newInterceptTargetProg()
			p.ensureInterceptDNSTarget([]string{})
			if (len(h.setCalls) > 0) != tc.want || len(h.resetCalls) != 0 {
				t.Fatalf("set=%v reset=%v", h.setCalls, h.resetCalls)
			}
		})
	}
}

func TestNativeCLATTargetUnknownPreservesStaticIPv4Cleanup(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.dhcpErr = errors.New("DHCP read failed")
	h.nativeErr = errors.New("native state unavailable")
	h.dns["Wi-Fi"] = []string{"192.0.2.53"}
	h.dns["Old service"] = []string{"127.0.0.53"}
	p := newInterceptTargetProg()
	persistInterceptTargetForTest(t, p, "Old service", "127.0.0.53")
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "" || !slices.Equal(h.resetCalls, []string{"Old service"}) || len(h.setCalls) != 0 || !slices.Equal(h.dns["Wi-Fi"], []string{"192.0.2.53"}) {
		t.Fatalf("existing static IPv4 cleanup changed: owner=%q reset=%v set=%v", p.interceptDNSTargetService, h.resetCalls, h.setCalls)
	}
}

func TestNativeCLATTargetTransitionAndReadFailure(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no DHCPv4 packet")
	h.dns["Wi-Fi"] = []string{"2001:db8::53"}
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "Wi-Fi" {
		t.Fatal("no target")
	}
	h.nativeErr = errors.New("store unavailable")
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "Wi-Fi" || len(h.setCalls) != 1 || len(h.resetCalls) != 0 {
		t.Fatal("unknown changed ownership")
	}
	h.nativeErr = nil
	h.dhcpErr = nil
	h.dhcp = []string{"192.168.1.1"}
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "" || !slices.Equal(h.dns["Wi-Fi"], []string{"2001:db8::53"}) {
		t.Fatal("dual stack did not restore IPv6 static DNS")
	}
}

// Use the real evidence reader: the native primary UUID is still checked,
// and the command-facing service is unambiguously mapped to its device.
func TestNativeCLATTargetExactPrimaryService(t *testing.T) {
	for _, static := range [][]string{{"9.9.9.9"}, {"2001:db8::53"}} {
		t.Run(strings.Join(static, ","), func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.dhcpErr = errors.New("no packet")
			h.serviceByDev["en1"] = "First Wi-Fi"
			h.dns["First Wi-Fi"] = nil
			h.dns["Primary Wi-Fi"] = slices.Clone(static)
			var calls []string
			out := nativeTargetTestOutputs()
			out[3] = nativeTargetTestServiceOrder("First Wi-Fi", "en9") + "(2) Primary Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)\n"
			outputs := append(out, out...)
			r := nativeTargetTestReader(t, outputs, &calls)
			interceptNativeCLATDefaultServiceFn = r.defaultService
			interceptPatchNetIfaceNameFn = func(*net.Interface) (bool, error) {
				t.Fatal("used first-match mapping for native fallback")
				return false, nil
			}
			var reads []string
			read := interceptNativeStaticDNSFn
			interceptNativeStaticDNSFn = func(ctx context.Context, iface *net.Interface) ([]string, error) {
				reads = append(reads, iface.Name)
				return read(ctx, iface)
			}
			p := newInterceptTargetProg()
			p.ensureInterceptDNSTarget([]string{})
			if !slices.Equal(reads, []string{"Primary Wi-Fi", "Primary Wi-Fi"}) || len(calls) != 10 {
				t.Fatalf("reads=%v calls=%v", reads, calls)
			}
			if len(h.dns["First Wi-Fi"]) != 0 {
				t.Fatal("inactive service mutated")
			}
			if hasIPv4DNS(static) {
				if !slices.Equal(h.dns["Primary Wi-Fi"], static) || len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
					t.Fatal("primary static IPv4 overwritten")
				}
			} else {
				if !slices.Equal(h.setCalls, []string{"Primary Wi-Fi"}) || p.interceptDNSTargetService != "Primary Wi-Fi" {
					t.Fatalf("set=%v ownership=%q", h.setCalls, p.interceptDNSTargetService)
				}
				p.removeInterceptDNSTarget("test shutdown")
				if !slices.Equal(h.dns["Primary Wi-Fi"], static) {
					t.Fatal("original static IPv6 not restored")
				}
			}
		})
	}
}

func TestNativeCLATTargetIdentityRecheck(t *testing.T) {
	for _, field := range []string{"UUID", "name", "device", "read error", "static DNS"} {
		t.Run(field, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.nativeCLAT = true
			h.dhcpErr = errors.New("no packet")
			p := newInterceptTargetProg()
			persistInterceptTargetForTest(t, p, "Old service", "127.0.0.53")
			h.dns["Old service"] = []string{"127.0.0.53"}
			read := interceptNativeCLATDefaultServiceFn
			calls := 0
			var shared context.Context
			interceptNativeCLATDefaultServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
				calls++
				if calls == 1 {
					shared = ctx
				} else if shared != ctx {
					t.Fatal("budget renewed on recheck")
				}
				svc, err := read(ctx, device)
				if calls == 2 {
					switch field {
					case "UUID":
						svc.ID = nativeTargetOtherServiceID
					case "name":
						svc.Name = "Other Wi-Fi"
					case "device":
						svc.Device = "en9"
					case "read error":
						err = errors.New("unknown")
					case "static DNS":
						h.dns["Wi-Fi"] = []string{"2001:db8::53"}
					}
				}
				return svc, err
			}
			p.ensureInterceptDNSTarget([]string{})
			if calls != 2 || len(h.setCalls) != 0 || len(h.resetCalls) != 0 || p.interceptDNSTargetService != "Old service" {
				t.Fatalf("uncertain recheck mutated state: calls=%d set=%v reset=%v owner=%q", calls, h.setCalls, h.resetCalls, p.interceptDNSTargetService)
			}
		})
	}
}

func TestNativeCLATTargetRestartListenerChangePreservesBackup(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no packet")
	backup := filepath.Join(t.TempDir(), ".dns_Wi-Fi")
	original := "2001:db8::53"
	if err := os.WriteFile(backup, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.statePath, []byte(`{"service":"Wi-Fi","value":"10.0.0.53"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h.dns["Wi-Fi"] = []string{"10.0.0.53"}
	var snapshots [][]string
	interceptSaveStaticDNSSnapshotFn = func(_ *net.Interface, snapshot []string, owned string) error {
		snapshots = append(snapshots, slices.Clone(snapshot))
		return saveTargetStaticDNSSnapshot(backup, snapshot, owned)
	}
	interceptSaveCurrentStaticDNSFn = func(*net.Interface) error { t.Fatal("legacy unvalidated snapshot read"); return nil }
	interceptSavedStaticNameserversFn = func(*net.Interface) []string {
		data, err := os.ReadFile(backup)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(string(data), ",")
	}
	p := newInterceptTargetProg()
	p.cfg.Listener["0"].IP, p.cfg.Listener["0"].Port = "10.0.0.54", 53
	p.ensureInterceptDNSTarget([]string{})
	if !slices.Equal(h.dns["Wi-Fi"], []string{"10.0.0.54"}) || p.interceptDNSTargetSetValue != "10.0.0.54" || len(snapshots) != 1 {
		t.Fatalf("listener migration failed: dns=%v target=%q snapshots=%v", h.dns["Wi-Fi"], p.interceptDNSTargetSetValue, snapshots)
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != original {
		t.Fatalf("original backup lost: %q %v", got, err)
	}
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 2 {
		t.Fatalf("target churn after reconciliation: %v", h.setCalls)
	}
	// A second restart must recover new ownership and still restore the original.
	restarted := newInterceptTargetProg()
	restarted.removeInterceptDNSTarget("shutdown")
	if !slices.Equal(h.dns["Wi-Fi"], []string{original}) || restarted.interceptDNSTargetService != "" {
		t.Fatalf("shutdown restored owned target: %v", h.dns["Wi-Fi"])
	}
	if _, err := os.Stat(h.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ownership not removed", err)
	}
}

func TestNativeCLATTargetSnapshotFailureRetainsOwnership(t *testing.T) {
	for _, mode := range []string{"write", "remove", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.nativeCLAT = true
			h.dhcpErr = errors.New("no packet")
			p := newInterceptTargetProg()
			persistInterceptTargetForTest(t, p, "Old service", "10.0.0.53")
			h.dns["Old service"] = []string{"10.0.0.53"}
			path := t.TempDir()
			if err := os.WriteFile(filepath.Join(path, "block"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "write" {
				h.dns["Wi-Fi"] = []string{"2001:db8::53"}
			}
			if mode == "cleanup" {
				path = filepath.Join(t.TempDir(), "backup")
				h.resetErr = errors.New("cleanup failed")
			}
			interceptSaveStaticDNSSnapshotFn = func(_ *net.Interface, snapshot []string, owned string) error {
				return saveTargetStaticDNSSnapshot(path, snapshot, owned)
			}
			p.ensureInterceptDNSTarget([]string{})
			if p.interceptDNSTargetService != "Old service" || len(h.setCalls) != 0 {
				t.Fatal("failed backup/cleanup lost old ownership")
			}
			if mode != "cleanup" && len(h.resetCalls) != 0 {
				t.Fatal("backup failure attempted cleanup")
			}
			if got := h.dns["Old service"]; !slices.Equal(got, []string{"10.0.0.53"}) {
				t.Fatal("old service changed", got)
			}
			if _, err := os.Stat(h.statePath); err != nil {
				t.Fatal("ownership file lost", err)
			}
		})
	}
}

func TestNativeCLATTargetRouteChange(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no packet")
	calls := 0
	interceptDefaultRouteInterfaceFn = func() (string, error) {
		calls++
		if calls > 1 {
			return "en9", nil
		}
		return "en1", nil
	}
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
		t.Fatal("route change mutated DNS")
	}
}

//go:build darwin

package ctrld

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestScopedOSResolverDoesNotBindDefaultSource(t *testing.T) {
	old4, old6 := GetDefaultLocalIPv4(), GetDefaultLocalIPv6()
	SetDefaultLocalIPv4(net.ParseIP("192.0.2.10"))
	SetDefaultLocalIPv6(net.ParseIP("2001:db8::10"))
	t.Cleanup(func() { SetDefaultLocalIPv4(old4); SetDefaultLocalIPv6(old6) })
	if got := defaultLocalIPForServer("[fe80::1%en0]:53"); got != nil {
		t.Fatalf("scoped resolver bound unrelated source %v", got)
	}
	if got := defaultLocalIPForServer("[2001:db8::53]:53"); !got.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("global IPv6 source changed: %v", got)
	}
	if got := defaultLocalIPForServer("192.0.2.53:53"); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("IPv4 source changed: %v", got)
	}
}

func TestScutilIPv6ProductionReader(t *testing.T) {
	old := scutilLocalAddresses
	t.Cleanup(func() { scutilLocalAddresses = old })
	localReads := 0
	scutilLocalAddresses = func() ([]netip.Addr, []netip.Addr, error) {
		localReads++
		return []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fe80::2%en0")},
			[]netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("fe80::1")}, nil
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' 'nameserver[0] : 2001:db8::53' 'nameserver[1] : fe80::1%en0' 'nameserver[2] : fe80::2%en0' 'nameserver[3] : ::1' 'nameserver[4] : 2001:db8::10'\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got := getDNSFromScutil(); !slices.Equal(got, []string{"2001:db8::53", "fe80::1%en0"}) {
		t.Fatalf("production reader lost IPv6: %v", got)
	}
	if localReads != 1 {
		t.Fatalf("local-address reads=%d, want 1", localReads)
	}
}

// While ctrld's own address is the only configured server, the full read
// retries scutil, and the quick read runs it once.
func TestScutilQuickReadDoesNotRetry(t *testing.T) {
	old := scutilLocalAddresses
	t.Cleanup(func() { scutilLocalAddresses = old })
	scutilLocalAddresses = func() ([]netip.Addr, []netip.Addr, error) {
		return nil, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	script := "#!/bin/sh\necho x >> '" + count + "'\nprintf '%s\\n' 'nameserver[0] : 127.0.0.1'\n"
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runs := func() int {
		b, _ := os.ReadFile(count)
		os.Remove(count)
		return len(b) / 2
	}
	for _, tc := range []struct {
		name string
		read func() []string
		want int
	}{
		{"quick", func() []string { return getDNSFromScutilAttempts(1) }, 1},
		{"full", getDNSFromScutil, 10},
	} {
		if got := tc.read(); len(got) != 0 {
			t.Fatalf("%s read = %v, want none", tc.name, got)
		}
		if got := runs(); got != tc.want {
			t.Fatalf("%s read ran scutil %d times, want %d", tc.name, got, tc.want)
		}
	}
}

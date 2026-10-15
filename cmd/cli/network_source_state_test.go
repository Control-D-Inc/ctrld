package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

func Test_interfaceAddressPrefix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address net.Addr
		want    string
	}{
		{"IPv4 with a 4-byte mask", &net.IPNet{IP: net.IPv4(192, 0, 2, 10).To4(), Mask: net.CIDRMask(24, 32)}, "192.0.2.10/24"},
		{"IPv4 in the 16-byte form with a 4-byte mask", &net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)}, "192.0.2.10/24"},
		{"IPv4 in the 16-byte form with a 16-byte mask", &net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(120, 128)}, "192.0.2.10/24"},
		{"IPv6 with a 64-bit mask", &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}, "2001:db8::1/64"},
		{"IPv4 without a mask", &net.IPAddr{IP: net.IPv4(192, 0, 2, 10)}, "192.0.2.10/32"},
		{"IPv6 without a mask", &net.IPAddr{IP: net.ParseIP("2001:db8::1")}, "2001:db8::1/128"},
		{"IPv4 with a nil mask", &net.IPNet{IP: net.IPv4(192, 0, 2, 10)}, "192.0.2.10/32"},
		{"IPv4 with an irregular mask", &net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.IPMask{255, 0, 255, 0}}, "192.0.2.10/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix, err := interfaceAddressPrefix(tc.address)
			if err != nil {
				t.Fatalf("interfaceAddressPrefix: %v", err)
			}
			if prefix.String() != tc.want {
				t.Fatalf("prefix = %s, want %s", prefix, tc.want)
			}
		})
	}
	if _, err := interfaceAddressPrefix(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 53}); err == nil {
		t.Fatal("a TCP address gave a prefix, want an error")
	}
}

// sourceTestInterfaces returns one up interface with a /24 and a /64 address,
// through the reader seam of networkSourceState.
func sourceTestInterfaces() ([]net.Interface, func(*net.Interface) ([]net.Addr, error)) {
	interfaces := []net.Interface{{Index: 1, Name: "en0", Flags: net.FlagUp}}
	addresses := func(iface *net.Interface) ([]net.Addr, error) {
		if iface.Name != "en0" {
			return nil, errors.New("unknown interface")
		}
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	return interfaces, addresses
}

func Test_networkSourceState_keepsTheMasks(t *testing.T) {
	state, err := networkSourceState(sourceTestInterfaces())
	if err != nil {
		t.Fatalf("networkSourceState: %v", err)
	}
	if !state.Interface["en0"].IsUp() {
		t.Fatal("en0 is not up")
	}
	if got := prefixStrings(state.InterfaceIPs["en0"]); !slices.Equal(got, []string{"192.0.2.10/24", "2001:db8::1/64"}) {
		t.Fatalf("prefixes = %v, want the /24 and the /64 with the host address", got)
	}
}

// stubSourceStateRead makes the fresh network read return the test interfaces
// through the real state builder.
func stubSourceStateRead(t *testing.T) {
	t.Helper()
	origRead := readNetworkSourceStateFn
	t.Cleanup(func() { readNetworkSourceStateFn = origRead })
	readNetworkSourceStateFn = func() (*netmon.State, error) { return networkSourceState(sourceTestInterfaces()) }
}

// Test_freshSnapshotAndHeaderKeepTheMasks proves that the send-time header and
// the fresh snapshot show the /24 and the /64 of the host, as the network
// monitor does.
func Test_freshSnapshotAndHeaderKeepTheMasks(t *testing.T) {
	stubHeaderSnapshotSources(t)
	stubSourceStateRead(t)
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	want := []string{"192.0.2.10/24", "2001:db8::1/64"}

	snapshot := buildNetworkSnapshot(p.freshSnapshotInputs())
	index := slices.IndexFunc(snapshot.Interfaces, func(i snapshotInterface) bool { return i.Name == "en0" })
	if index < 0 {
		t.Fatalf("snapshot holds no en0: %+v", snapshot.Interfaces)
	}
	if got := snapshot.Interfaces[index].IPs; !slices.Equal(got, want) {
		t.Fatalf("snapshot ips = %v, want %v", got, want)
	}

	parsed, _ := parseLogHeader(t, p.sendLogHeader())
	var headerIPs []string
	for _, iface := range parsed.Network.Interfaces {
		if iface.Name == "en0" {
			headerIPs = iface.IPs
		}
	}
	if !slices.Equal(headerIPs, want) {
		t.Fatalf("header ips = %v, want %v", headerIPs, want)
	}
}

// Test_sourceValidationKeepsTheHostAddress proves that a state with masked
// prefixes still names the host address, not the subnet address, as the
// source of the process.
func Test_sourceValidationKeepsTheHostAddress(t *testing.T) {
	before4, before6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	t.Cleanup(func() {
		ctrld.SetDefaultLocalIPv4(context.Background(), before4)
		ctrld.SetDefaultLocalIPv6(context.Background(), before6)
	})
	state, err := networkSourceState(sourceTestInterfaces())
	if err != nil {
		t.Fatalf("networkSourceState: %v", err)
	}

	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.10"))
	ctrld.SetDefaultLocalIPv6(context.Background(), net.ParseIP("2001:db8::1"))
	validateDefaultLocalIPsFromDelta(context.Background(), state, 1)
	if got := ctrld.GetDefaultLocalIPv4(); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("source IPv4 = %v, want the host address kept", got)
	}
	if got := ctrld.GetDefaultLocalIPv6(); !got.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("source IPv6 = %v, want the host address kept", got)
	}

	// The subnet address is not an address of the host.
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.0"))
	validateDefaultLocalIPsFromDelta(context.Background(), state, 2)
	if got := ctrld.GetDefaultLocalIPv4(); got != nil {
		t.Fatalf("source IPv4 = %v, want the subnet address cleared", got)
	}
	if reason := sourceInvalidReason(state, netip.MustParseAddr("192.0.2.10").AsSlice()); reason != "" {
		t.Fatalf("host address reported %q, want a valid source", reason)
	}
}

package cli

import (
	"context"
	"net"
	"strings"
	"testing"
)

// Captured macOS 15.7.7 CLAT dictionaries; UUID and interface IPv6 addresses
// are sanitized. Keep the native field shapes, including nested routes.
func TestCapturedCLATNativeReader(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	const global = `<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 11111111-2222-3333-4444-555555555555
  Router : 192.0.0.1
}`
	const state = `<dictionary> {
  AdditionalRoutes : <array> {
    0 : <dictionary> {
      DestinationAddress : 192.0.0.2
      SubnetMask : 255.255.255.255
    }
  }
  Addresses : <array> {
    0 : 192.0.0.2
  }
  CLAT46 : TRUE
  InterfaceName : en0
  Router : 192.0.0.1
}`
	const setup = `<dictionary> {
  UserDefinedName : Wi-Fi
}`
	iface := &net.Interface{Name: "en0", Flags: net.FlagUp | net.FlagRunning}
	var addrs []net.Addr
	for _, s := range []string{"192.0.0.2/32", "fe80::1/64", "2001:db8::1/64", "2001:db8::2/64", "2001:db8::3/64"} {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		addrs = append(addrs, n)
	}
	calls := 0
	reader := nativeTargetReader{
		run: func(_ context.Context, input, path string, args ...string) ([]byte, error) {
			calls++
			if path == "/usr/sbin/networksetup" && len(args) == 1 && args[0] == "-listnetworkserviceorder" && input == "" {
				return []byte(nativeTargetTestServiceOrder("Wi-Fi", "en0")), nil
			}
			if path != "/usr/sbin/scutil" || len(args) != 0 {
				t.Fatal("unexpected command")
			}
			switch strings.TrimSpace(input) {
			case "show State:/Network/Global/IPv4\nquit":
				return []byte(global), nil
			case "show State:/Network/Service/" + id + "/IPv4\nquit":
				return []byte(state), nil
			case "show Setup:/Network/Service/" + id + "\nquit":
				return []byte(setup), nil
			default:
				t.Fatal("unexpected key", input)
				return nil, nil
			}
		},
		interfaceByName: func(name string) (*net.Interface, error) {
			if name != "en0" {
				t.Fatal(name)
			}
			return iface, nil
		},
		interfaceAddrs: func(got *net.Interface) ([]net.Addr, error) {
			if got != iface {
				t.Fatal("wrong interface")
			}
			return addrs, nil
		},
	}
	got, err := reader.defaultService(context.Background(), "en0")
	want := nativeTargetService{ID: id, Name: "Wi-Fi", Device: "en0"}
	if err != nil || got != want || calls != 5 {
		t.Fatalf("got=%+v err=%v reads=%d", got, err, calls)
	}
	t.Log("Captured native dictionaries accepted; primary Wi-Fi service on en0 selected")
}

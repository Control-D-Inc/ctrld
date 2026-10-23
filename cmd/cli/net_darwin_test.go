package cli

import (
	"strings"
	"testing"
	"time"
)

const listAllHardwarePortsFixture = `
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: a0:78:17:68:56:3f

Hardware Port: iPhone USB
Device: en7
Ethernet Address: 6e:5a:6b:12:34:56

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:21:bb:3a:7a:40

Hardware Port: Ethernet Adapter (en6)
Device: en6
Ethernet Address: 3a:3e:fc:1e:ab:41

Hardware Port: com.wireguard.macos
Device:

VLAN Configurations
===================
`

const listNetworkServiceOrderFixture = `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) iPhone USB
(Hardware Port: iPhone USB, Device: en7)

(3) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(*) Ethernet Adapter (en6)
(Hardware Port: Ethernet Adapter (en6), Device: en6)

(4) ca-001-stg
(Hardware Port: com.wireguard.macos, Device: )

`

func Test_parseHardwarePorts(t *testing.T) {
	ports := parseHardwarePorts(strings.NewReader(listAllHardwarePortsFixture))
	addServiceNames(ports, strings.NewReader(listNetworkServiceOrderFixture))

	tests := []struct {
		device      string
		wantPort    string
		wantService string
	}{
		{"en0", "Wi-Fi", "Wi-Fi"},
		{"en7", "iPhone USB", "iPhone USB"},
		{"bridge0", "Thunderbolt Bridge", "Thunderbolt Bridge"},
		{"en6", "Ethernet Adapter (en6)", ""},
	}
	if len(ports) != len(tests) {
		t.Fatalf("parseHardwarePorts returned %d devices, want %d: %v", len(ports), len(tests), ports)
	}
	for _, tc := range tests {
		t.Run(tc.device, func(t *testing.T) {
			info := ports[tc.device]
			if info.Port != tc.wantPort {
				t.Errorf("port of %s = %q, want %q", tc.device, info.Port, tc.wantPort)
			}
			if info.Service != tc.wantService {
				t.Errorf("service of %s = %q, want %q", tc.device, info.Service, tc.wantService)
			}
		})
	}
}

func Test_networkServiceName(t *testing.T) {
	tests := []struct {
		device string
		want   string
	}{
		{"en0", "Wi-Fi"},
		{"en7", "iPhone USB"},
		{"bridge0", "Thunderbolt Bridge"},
		{"en6", ""},
		{"en9", ""},
	}
	for _, tc := range tests {
		t.Run(tc.device, func(t *testing.T) {
			got := networkServiceName(tc.device, strings.NewReader(listNetworkServiceOrderFixture))
			if got != tc.want {
				t.Errorf("networkServiceName(%q) = %q, want %q", tc.device, got, tc.want)
			}
		})
	}
}

func Test_parseHardwarePorts_dropsATruncatedRead(t *testing.T) {
	longLine := strings.Repeat("x", maxNetworksetupLine+1)

	if got := parseHardwarePorts(strings.NewReader(listAllHardwarePortsFixture + longLine)); got != nil {
		t.Errorf("parseHardwarePorts of a truncated read = %v, want nil", got)
	}
	if got := serviceNamesByDevice(strings.NewReader(listNetworkServiceOrderFixture + longLine)); got != nil {
		t.Errorf("serviceNamesByDevice of a truncated read = %v, want nil", got)
	}
}

func Test_readBoundedOutput(t *testing.T) {
	out, err := readBoundedOutput(strings.NewReader(listAllHardwarePortsFixture))
	if err != nil || string(out) != listAllHardwarePortsFixture {
		t.Fatalf("readBoundedOutput of the fixture = %q, %v, want the fixture and no error", out, err)
	}
	if _, err := readBoundedOutput(strings.NewReader(strings.Repeat("x", maxNetworksetupOutput+1))); err == nil {
		t.Fatal("readBoundedOutput of an output above the bound gave no error")
	}
}

// stubHardwarePorts replaces the command and clock seams of the hardware port
// cache, and restores them with the cache itself.
func stubHardwarePorts(t *testing.T, read func() map[string]hardwarePortInfo, now func() time.Time) {
	t.Helper()
	readBefore, nowBefore := readHardwarePortsFn, hardwarePortsNowFn
	hardwarePortsMu.Lock()
	cacheBefore, readAtBefore := hardwarePortsCache, hardwarePortsReadAt
	hardwarePortsCache, hardwarePortsReadAt = nil, time.Time{}
	hardwarePortsMu.Unlock()
	t.Cleanup(func() {
		readHardwarePortsFn, hardwarePortsNowFn = readBefore, nowBefore
		hardwarePortsMu.Lock()
		hardwarePortsCache, hardwarePortsReadAt = cacheBefore, readAtBefore
		hardwarePortsMu.Unlock()
	})
	readHardwarePortsFn, hardwarePortsNowFn = read, now
}

func Test_hardwarePortsByDevice_caches(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reads := 0
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		reads++
		return map[string]hardwarePortInfo{"en0": {Port: "Wi-Fi", Service: "Wi-Fi"}}
	}, func() time.Time { return now })

	if got := hardwarePortsByDevice()["en0"].Port; got != "Wi-Fi" {
		t.Fatalf("first read port = %q, want Wi-Fi", got)
	}
	now = now.Add(59 * time.Second)
	hardwarePortsByDevice()
	if reads != 1 {
		t.Fatalf("reads within the cache window = %d, want 1", reads)
	}
	now = now.Add(2 * time.Second)
	hardwarePortsByDevice()
	if reads != 2 {
		t.Fatalf("reads after the cache window = %d, want 2", reads)
	}
}

func Test_hardwarePortsByDevice_keepsLastGoodRead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fail := false
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		if fail {
			return nil
		}
		return map[string]hardwarePortInfo{"en0": {Port: "Wi-Fi"}}
	}, func() time.Time { return now })

	hardwarePortsByDevice()
	fail = true
	now = now.Add(2 * time.Minute)
	if got := hardwarePortsByDevice()["en0"].Port; got != "Wi-Fi" {
		t.Fatalf("port after a failed read = %q, want Wi-Fi", got)
	}
}

func Test_hardwarePortsByDevice_keepsTheWindowAfterAFailedRead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reads := 0
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		reads++
		return nil
	}, func() time.Time { return now })

	hardwarePortsByDevice()
	now = now.Add(time.Second)
	hardwarePortsByDevice()
	if reads != 1 {
		t.Fatalf("reads of a failing command within the window = %d, want 1", reads)
	}
	now = now.Add(2 * time.Minute)
	hardwarePortsByDevice()
	if reads != 2 {
		t.Fatalf("reads after the window = %d, want 2", reads)
	}
}

func Test_refreshInterfaceMeta_dropsTheReadWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reads := 0
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		reads++
		return map[string]hardwarePortInfo{"en0": {Port: "Wi-Fi"}}
	}, func() time.Time { return now })

	hardwarePortsByDevice()
	hardwarePortsByDevice()
	if reads != 1 {
		t.Fatalf("reads within the window = %d, want 1", reads)
	}
	refreshInterfaceMeta()
	if got := hardwarePortsByDevice()["en0"].Port; got != "Wi-Fi" {
		t.Fatalf("port after a refresh = %q, want Wi-Fi", got)
	}
	if reads != 2 {
		t.Fatalf("reads after a refresh = %d, want 2", reads)
	}
}

func Test_hardwarePortsByDevice_readsOutsideTheLock(t *testing.T) {
	now := time.Unix(1700000000, 0)
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		// A command runs outside the mutex, so this read can take it.
		if !hardwarePortsMu.TryLock() {
			t.Error("the command ran under the hardware ports mutex")
		} else {
			hardwarePortsMu.Unlock()
		}
		return map[string]hardwarePortInfo{"en0": {Port: "Wi-Fi"}}
	}, func() time.Time { return now })

	if got := hardwarePortsByDevice()["en0"].Port; got != "Wi-Fi" {
		t.Fatalf("port = %q, want Wi-Fi", got)
	}
}

// fixtureHardwarePorts returns the port map of the two command fixtures.
func fixtureHardwarePorts() map[string]hardwarePortInfo {
	ports := parseHardwarePorts(strings.NewReader(listAllHardwarePortsFixture))
	addServiceNames(ports, strings.NewReader(listNetworkServiceOrderFixture))
	return ports
}

func Test_transitionTestGlobalsReadNoPorts(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reads := 0
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		reads++
		return fixtureHardwarePorts()
	}, func() time.Time { return now })

	TestNetworkChangeDoesNotRestoreDownDefaultRouteSources(t)
	TestNetworkChangeSourceMovedToUpInterface(t)

	if reads != 0 {
		t.Fatalf("port reads of two transition tests = %d, want 0", reads)
	}
}

func Test_platformInterfaceMeta(t *testing.T) {
	now := time.Unix(1700000000, 0)
	stubHardwarePorts(t, func() map[string]hardwarePortInfo {
		return map[string]hardwarePortInfo{"en7": {Port: "iPhone USB", Service: "iPhone USB"}}
	}, func() time.Time { return now })

	class, hardwarePort, service := platformInterfaceMeta("en7")
	if class != "" {
		t.Errorf("class = %q, want empty", class)
	}
	if hardwarePort != "iPhone USB" || service != "iPhone USB" {
		t.Errorf("port, service = %q, %q, want iPhone USB twice", hardwarePort, service)
	}
	if class, hardwarePort, service = platformInterfaceMeta("utun3"); class != "" || hardwarePort != "" || service != "" {
		t.Errorf("unknown device gave %q, %q, %q, want empty strings", class, hardwarePort, service)
	}
	if platformVirtualInterfaces() != nil {
		t.Error("platformVirtualInterfaces is not nil on darwin")
	}
}

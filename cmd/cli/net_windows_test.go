package cli

import (
	"bufio"
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

func Test_validInterfaces(t *testing.T) {
	verbose = 3
	initConsoleLogging()
	start := time.Now()
	im := ctrld.ValidInterfaces(ctrld.LoggerCtx(context.Background(), mainLog.Load()))
	t.Logf("Using Windows API takes: %d", time.Since(start).Milliseconds())
	ifaces := slices.Collect(maps.Keys(im))

	start = time.Now()
	ifacesPowershell := validInterfacesPowershell()
	t.Logf("Using Powershell takes: %d", time.Since(start).Milliseconds())

	slices.Sort(ifaces)
	slices.Sort(ifacesPowershell)
	if !slices.Equal(ifaces, ifacesPowershell) {
		t.Fatalf("result mismatch, want: %v, got: %v", ifacesPowershell, ifaces)
	}
}

func validInterfacesPowershell() []string {
	out, err := powershell("Get-NetAdapter -Physical | Select-Object -ExpandProperty Name")
	if err != nil {
		return nil
	}
	var res []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		ifaceName := strings.TrimSpace(scanner.Text())
		res = append(res, ifaceName)
	}
	return res
}

func Test_adapterClass(t *testing.T) {
	tests := []struct {
		name    string
		adapter adapterInfo
		want    string
	}{
		{"virtual without a connector", adapterInfo{Virtual: true}, "virtual"},
		{"virtual with a connector", adapterInfo{Virtual: true, ConnectorPresent: true}, "hardware"},
		{"physical adapter", adapterInfo{ConnectorPresent: true, Hardware: true}, "hardware"},
		{"unknown adapter", adapterInfo{}, "hardware"},
		{"tap driver", adapterInfo{Description: "TAP-Windows Adapter V9", Virtual: true}, "tunnel"},
		{"wintun driver", adapterInfo{Description: "Wintun Userspace Tunnel", Virtual: true}, "tunnel"},
		{"wireguard driver", adapterInfo{Description: "WireGuard Tunnel #1", Virtual: true}, "tunnel"},
		{"vpn description", adapterInfo{Description: "Cisco AnyConnect VPN Adapter", ConnectorPresent: true}, "tunnel"},
		{"lower case description", adapterInfo{Description: "openvpn tap-windows6"}, "tunnel"},
		{"ethernet adapter", adapterInfo{Description: "Intel(R) Ethernet Connection I219-V", ConnectorPresent: true, Hardware: true}, "hardware"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := adapterClass(tc.adapter); got != tc.want {
				t.Errorf("adapterClass(%+v) = %q, want %q", tc.adapter, got, tc.want)
			}
		})
	}
}

// stubAdapters replaces the WMI and clock seams of the adapter cache, and
// restores them with the cache itself.
func stubAdapters(t *testing.T, read func() []adapterInfo, now func() time.Time) {
	t.Helper()
	readBefore, nowBefore := readAdaptersFn, adapterCacheNowFn
	adapterCacheMu.Lock()
	cacheBefore, readAtBefore := adapterCache, adapterCacheReadAt
	adapterCache, adapterCacheReadAt = nil, time.Time{}
	adapterCacheMu.Unlock()
	t.Cleanup(func() {
		readAdaptersFn, adapterCacheNowFn = readBefore, nowBefore
		adapterCacheMu.Lock()
		adapterCache, adapterCacheReadAt = cacheBefore, readAtBefore
		adapterCacheMu.Unlock()
	})
	readAdaptersFn, adapterCacheNowFn = read, now
}

func Test_adapterCache(t *testing.T) {
	now := time.Unix(1700000000, 0)
	reads := 0
	stubAdapters(t, func() []adapterInfo {
		reads++
		return []adapterInfo{
			{Name: "Ethernet", Description: "Intel I219-V", ConnectorPresent: true, Hardware: true},
			{Name: "Hyper-V Switch", Description: "Hyper-V Virtual Switch", Virtual: true},
		}
	}, func() time.Time { return now })

	if got := adapters(); len(got) != 2 || got[0].Name != "Ethernet" {
		t.Fatalf("adapters = %v, want the two fixture adapters", got)
	}
	now = now.Add(59 * time.Second)
	adapters()
	if reads != 1 {
		t.Fatalf("reads within the cache window = %d, want 1", reads)
	}
	now = now.Add(2 * time.Second)
	adapters()
	if reads != 2 {
		t.Fatalf("reads after the cache window = %d, want 2", reads)
	}
	refreshInterfaceMeta()
	if reads != 2 {
		t.Fatalf("reads for a refresh alone = %d, want 2", reads)
	}
	adapters()
	if reads != 3 {
		t.Fatalf("reads after a refresh = %d, want 3", reads)
	}

	virtual := platformVirtualInterfaces()
	if _, ok := virtual["Hyper-V Switch"]; !ok || len(virtual) != 1 {
		t.Fatalf("platformVirtualInterfaces = %v, want the virtual switch only", virtual)
	}
	class, hardwarePort, service := platformInterfaceMeta("Ethernet")
	if class != "hardware" || hardwarePort != "Intel I219-V" || service != "" {
		t.Fatalf("platformInterfaceMeta = %q, %q, %q, want hardware, Intel I219-V, empty", class, hardwarePort, service)
	}
}

func Test_adapterCacheReadsOnceForTwoCallers(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var mu sync.Mutex
	reads := 0
	stubAdapters(t, func() []adapterInfo {
		mu.Lock()
		reads++
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		return []adapterInfo{{Name: "Ethernet", Description: "Intel I219-V", ConnectorPresent: true, Hardware: true}}
	}, func() time.Time { return now })

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			adapters()
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if reads != 1 {
		t.Fatalf("queries for four callers = %d, want 1", reads)
	}
}

func Test_adapterCacheKeepsTheRemovedAdapter(t *testing.T) {
	now := time.Unix(1700000000, 0)
	removed := false
	stubAdapters(t, func() []adapterInfo {
		read := []adapterInfo{{Name: "Ethernet", Description: "Intel I219-V", ConnectorPresent: true, Hardware: true}}
		if removed {
			return read
		}
		return append(read, adapterInfo{Name: "WireGuard", Description: "WireGuard Tunnel #1", Virtual: true})
	}, func() time.Time { return now })

	adapters()
	removed = true
	refreshInterfaceMeta()

	class, hardwarePort, _ := platformInterfaceMeta("WireGuard")
	if class != "tunnel" || hardwarePort != "WireGuard Tunnel #1" {
		t.Fatalf("meta of the removed adapter = %q, %q, want tunnel, WireGuard Tunnel #1", class, hardwarePort)
	}
	if class, _, _ := platformInterfaceMeta("Absent"); class != "" {
		t.Fatalf("meta of an adapter that no read named = %q, want empty", class)
	}
}

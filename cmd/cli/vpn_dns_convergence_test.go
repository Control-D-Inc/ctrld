package cli

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

func TestVPNDNSLongestNormalizedSuffixAcrossRefreshes(t *testing.T) {
	for _, routeOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "route-only"}[routeOnly], func(t *testing.T) {
			m := newVPNDNSManager(nil)
			m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
				return []ctrld.VPNDNSConfig{
					{Domains: []string{".EXAMPLE.com."}, Servers: []string{"10.0.0.1"}},
					{Domains: []string{"~Child.Example.COM."}, Servers: []string{"10.0.0.2", "10.0.0.3"}},
					{Domains: []string{".", "~."}, Servers: []string{"10.0.0.4"}},
				}
			}
			if routeOnly {
				m.RefreshRoutesOnly()
			} else {
				m.Refresh(true)
			}
			for query, want := range map[string][]string{
				"example.com.": {"10.0.0.1"}, "other.example.com": {"10.0.0.1"},
				"child.example.com.":           {"10.0.0.2", "10.0.0.3"},
				"HOST.Deep.Child.Example.COM.": {"10.0.0.2", "10.0.0.3"},
				"notexample.com.":              nil, "example.com.other.": nil, "public.test.": nil,
			} {
				for i := 0; i < 1000; i++ {
					if got := m.UpstreamForDomain(query); !reflect.DeepEqual(got, want) {
						t.Fatalf("%s: got %v want %v", query, got, want)
					}
				}
			}
			got := m.UpstreamForDomain("child.example.com")
			got[0] = "mutated"
			if m.UpstreamForDomain("child.example.com")[0] != "10.0.0.2" {
				t.Fatal("lookup leaked mutable slice")
			}
		})
	}
}

// Drive the real poller diff -> journal callback -> manager discovery path.
// Both OS boundaries are fixtures, so this test cannot touch host DNS or PF.
func TestVPNDNSJournalLatePublicationConverges(t *testing.T) {
	m := newVPNDNSManager(nil)
	var discoveryCalls, updates int
	var snapshot []ctrld.VPNDNSConfig
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { discoveryCalls++; return snapshot }
	m.onServersChanged = func([]vpnDNSExemption) error { updates++; return nil }
	p := &prog{vpnDNS: m, csSetDnsDone: make(chan struct{})}
	close(p.csSetDnsDone)
	var table []dnsResolverEntry
	poller := newDNSConfigPoller(func() ([]dnsResolverEntry, error) { return table, nil })
	emit := func() { p.logDNSConfigChanges(poller.pollOnce(time.Now())) }
	emit() // empty startup baseline
	for _, server := range []string{"10.0.0.1", "10.0.0.2"} {
		snapshot = []ctrld.VPNDNSConfig{{InterfaceName: "utun-fixture", Domains: []string{"corp.example."}, Servers: []string{server}}}
		table = []dnsResolverEntry{{Interface: "utun-fixture", Nameservers: []string{server}}}
		emit()
		if got := m.UpstreamForDomain("host.corp.example."); len(got) != 1 || got[0] != server {
			t.Fatalf("late DNS-only change not published: %v", got)
		}
		for i := 0; i < 100; i++ {
			emit()
		}
	}
	if discoveryCalls != 2 || updates != 2 {
		t.Fatalf("unchanged tables caused refresh storm: discoveries=%d updates=%d", discoveryCalls, updates)
	}
	// Removal is a DNS-only delta too; keep Windows' one-empty-snapshot guard.
	snapshot = nil
	table = nil
	emit()
	if vpnDNSSettlingEnabled { // Preserve Windows' one-empty-snapshot guard.
		m.Refresh(true)
	}
	if got := m.UpstreamForDomain("host.corp.example"); len(got) != 0 {
		t.Fatalf("removed DNS retained: %v", got)
	}
	p.closeNetMonitor()
}

func TestVPNDNSJournalShutdownDrainsAndRejectsRefresh(t *testing.T) {
	m := newVPNDNSManager(nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls, updates atomic.Int32
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		calls.Add(1)
		close(entered)
		<-release
		return []ctrld.VPNDNSConfig{{Domains: []string{"corp.example"}, Servers: []string{"10.0.0.1"}}}
	}
	m.onServersChanged = func([]vpnDNSExemption) error { updates.Add(1); return nil }
	p := &prog{vpnDNS: m, csSetDnsDone: make(chan struct{})}
	entries := []dnsResolverEntry{{Action: resolverActionChanged}}
	p.logDNSConfigChanges(entries)
	if calls.Load() != 0 {
		t.Fatal("discovery ran before DNS initialization")
	}
	close(p.csSetDnsDone)
	callbackDone := make(chan struct{})
	go func() { defer close(callbackDone); p.logDNSConfigChanges(entries) }()
	<-entered
	stopDone := make(chan struct{})
	go func() { p.closeNetMonitor(); close(stopDone) }()
	<-p.networkActivityDone()
	select {
	case <-stopDone:
		t.Fatal("shutdown did not drain in-flight refresh")
	default:
	}
	close(release)
	<-callbackDone
	<-stopDone
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.logDNSConfigChanges(entries) }()
	}
	wg.Wait()
	if calls.Load() != 1 || updates.Load() != 1 {
		t.Fatalf("post-stop mutation: discovery=%d updates=%d", calls.Load(), updates.Load())
	}
}

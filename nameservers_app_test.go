package ctrld

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
)

func setAppNameserversForTest(t *testing.T, nss []string) {
	t.Helper()
	SetAppNameservers(context.Background(), nss)
	t.Cleanup(func() { SetAppNameservers(context.Background(), nil) })
}

func TestAppNameserversReplaceDiscovery(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"keeps order", []string{"192.168.1.1", "2606:4700::1111"}, []string{"192.168.1.1", "2606:4700::1111"}},
		{"drops invalid and duplicate", []string{" 10.0.0.1 ", "dns.example", "", "10.0.0.1"}, []string{"10.0.0.1"}},
		{"keeps zone", []string{"fe80::1%en0"}, []string{"fe80::1%en0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setAppNameserversForTest(t, tc.in)
			if got := nameservers(context.Background()); !slices.Equal(got, tc.want) {
				t.Errorf("nameservers() = %v, want %v", got, tc.want)
			}
			if got := quickNameservers(context.Background()); !slices.Equal(got, tc.want) {
				t.Errorf("quickNameservers() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAppNameserversEmptyGoesBackToDiscovery(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"not-an-ip"}} {
		setAppNameserversForTest(t, []string{"10.0.0.1"})
		SetAppNameservers(context.Background(), in)
		if nss := AppNameservers(); nss != nil {
			t.Errorf("SetAppNameservers(%q) kept %v", in, nss)
		}
	}
}

func TestOsResolverUsesAppNameservers(t *testing.T) {
	setAppNameserversForTest(t, []string{"192.168.255.53"})
	effective, system := InitializeOsResolverWithSystemNameserversReason(context.Background(), true, "test")
	if !slices.Equal(system, []string{"192.168.255.53"}) {
		t.Fatalf("system nameservers = %v", system)
	}
	if !slices.Contains(effective, "192.168.255.53:53") {
		t.Fatalf("OS resolver nameservers = %v", effective)
	}
}

// The app reports a network change on its own thread while queries run.
func TestAppNameserversConcurrentUpdate(t *testing.T) {
	t.Cleanup(func() { SetAppNameservers(context.Background(), nil) })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			SetAppNameservers(context.Background(), []string{"10.0.0.1", "10.0.0.2"})
		}()
		go func() {
			defer wg.Done()
			if nss := AppNameservers(); nss != nil && len(nss) != 2 {
				t.Errorf("read a partial list: %v", nss)
			}
		}()
	}
	wg.Wait()
}

// An app that sends host:port values or names must see why ctrld drops them.
func TestParseNameserversLogsDroppedValues(t *testing.T) {
	ctx, logs := captureProxyLog(t)
	got := ParseNameservers(ctx, []string{"192.168.1.1:53", " ", "dns.example", "10.0.0.1"})
	if !slices.Equal(got, []string{"10.0.0.1"}) {
		t.Errorf("ParseNameservers() = %v, want [10.0.0.1]", got)
	}
	for _, dropped := range []string{"192.168.1.1:53", "dns.example"} {
		if !strings.Contains(logs.String(), dropped) {
			t.Errorf("log has no line for the dropped value %q:\n%s", dropped, logs.String())
		}
	}
}

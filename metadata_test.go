package ctrld

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld/internal/system"
)

func Test_metadata(t *testing.T) {
	m := SystemMetadata(context.Background())
	t.Logf("metadata: %v", m)
}

func TestSystemMetadataUsernameScope(t *testing.T) {
	oldMain, oldSession := discoverMainUserFn, discoverSessionUserFn
	t.Cleanup(func() { discoverMainUserFn, discoverSessionUserFn = oldMain, oldSession })

	var mainCalls int
	discoverMainUserFn = func(context.Context) string {
		mainCalls++
		return "lowest-uid-guess"
	}

	t.Run("startup with no login session omits username", func(t *testing.T) {
		mainCalls = 0
		discoverSessionUserFn = func(context.Context) string { return "" }
		m := SystemMetadataStartup(context.Background())
		if v, ok := m[metadataUsernameKey]; ok {
			t.Errorf("startup metadata sent username %q with no login session; the API would overwrite the stored value", v)
		}
		if mainCalls != 0 {
			t.Error("startup ran the account-list fallbacks")
		}
	})

	t.Run("startup with a login session sends that user", func(t *testing.T) {
		discoverSessionUserFn = func(context.Context) string { return "session-user" }
		if got := SystemMetadataStartup(context.Background())[metadataUsernameKey]; got != "session-user" {
			t.Errorf("startup username = %q, want %q", got, "session-user")
		}
	})

	t.Run("provisioning keeps the full discovery chain", func(t *testing.T) {
		discoverSessionUserFn = func(context.Context) string { return "" }
		if got := SystemMetadata(context.Background())[metadataUsernameKey]; got != "lowest-uid-guess" {
			t.Errorf("provisioning username = %q, want the full-discovery result", got)
		}
	})

	t.Run("runtime omits username", func(t *testing.T) {
		mainCalls = 0
		discoverSessionUserFn = func(context.Context) string {
			t.Error("runtime ran session discovery")
			return "session-user"
		}
		if _, ok := SystemMetadataRuntime(context.Background())[metadataUsernameKey]; ok || mainCalls != 0 {
			t.Error("runtime metadata included or discovered username")
		}
	})

	t.Run("startup carries the same non-username keys as runtime", func(t *testing.T) {
		discoverSessionUserFn = func(context.Context) string { return "" }
		if s, r := SystemMetadataStartup(context.Background()), SystemMetadataRuntime(context.Background()); !reflect.DeepEqual(s, r) {
			t.Errorf("startup %v and runtime %v differ beyond username", s, r)
		}
	})
}

func TestChassisValuesIsSafeForConcurrentCalls(t *testing.T) {
	oldType, oldVendor, oldLookup := chassisType, chassisVendor, getChassisInfoFn
	t.Cleanup(func() { chassisType, chassisVendor, getChassisInfoFn = oldType, oldVendor, oldLookup })

	chassisType, chassisVendor = "", ""
	var lookups atomic.Int32
	getChassisInfoFn = func() (*system.ChassisInfo, error) {
		lookups.Add(1)
		time.Sleep(10 * time.Millisecond)
		return &system.ChassisInfo{Type: "Laptop", Vendor: "Acme"}, nil
	}

	const callers = 16
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(callers)
	done.Add(callers)
	kinds, vendors := make([]string, callers), make([]string, callers)
	for i := range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			kinds[i], vendors[i] = chassisValues(NopLogger)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	if got := lookups.Load(); got != 1 {
		t.Errorf("chassis lookup ran %d times, want 1", got)
	}
	for i := range callers {
		if kinds[i] != "Laptop" || vendors[i] != "Acme" {
			t.Errorf("caller %d got chassis %q/%q, want Laptop/Acme", i, kinds[i], vendors[i])
		}
	}
}

func TestChassisValuesRetriesAfterFailedLookup(t *testing.T) {
	oldType, oldVendor, oldLookup := chassisType, chassisVendor, getChassisInfoFn
	t.Cleanup(func() { chassisType, chassisVendor, getChassisInfoFn = oldType, oldVendor, oldLookup })

	chassisType, chassisVendor = "", ""
	fail := true
	getChassisInfoFn = func() (*system.ChassisInfo, error) {
		if fail {
			return nil, errors.New("no chassis")
		}
		return &system.ChassisInfo{Type: "Desktop", Vendor: "Acme"}, nil
	}
	if kind, vendor := chassisValues(NopLogger); kind != "" || vendor != "" {
		t.Fatalf("failed lookup returned %q/%q, want empty", kind, vendor)
	}
	fail = false
	if kind, vendor := chassisValues(NopLogger); kind != "Desktop" || vendor != "Acme" {
		t.Errorf("retry returned %q/%q, want Desktop/Acme", kind, vendor)
	}
}

func TestChassisValuesKeepsResultWithOneEmptyValue(t *testing.T) {
	oldType, oldVendor, oldLookup := chassisType, chassisVendor, getChassisInfoFn
	t.Cleanup(func() { chassisType, chassisVendor, getChassisInfoFn = oldType, oldVendor, oldLookup })

	chassisType, chassisVendor = "", ""
	var lookups int
	getChassisInfoFn = func() (*system.ChassisInfo, error) {
		lookups++
		return &system.ChassisInfo{Type: "", Vendor: "Acme"}, nil
	}
	chassisValues(NopLogger)
	if kind, vendor := chassisValues(NopLogger); kind != "" || vendor != "Acme" {
		t.Errorf("chassisValues = %q/%q, want empty/Acme", kind, vendor)
	}
	if lookups != 1 {
		t.Errorf("chassis lookup ran %d times, want 1", lookups)
	}
}

func TestSystemMetadataSkipsChassisLookupOnMobile(t *testing.T) {
	oldType, oldVendor, oldLookup, oldIOS := chassisType, chassisVendor, getChassisInfoFn, isIOS
	t.Cleanup(func() {
		chassisType, chassisVendor, getChassisInfoFn, isIOS = oldType, oldVendor, oldLookup, oldIOS
	})

	chassisType, chassisVendor = "", ""
	isIOS = func() bool { return true }
	getChassisInfoFn = func() (*system.ChassisInfo, error) {
		t.Error("chassis lookup ran on mobile")
		return &system.ChassisInfo{Type: "Laptop", Vendor: "Acme"}, nil
	}
	for name, collect := range map[string]func(context.Context) map[string]string{
		"provisioning": SystemMetadata,
		"startup":      SystemMetadataStartup,
		"runtime":      SystemMetadataRuntime,
	} {
		m := collect(context.Background())
		if m[metadataChassisTypeKey] != "" || m[metadataChassisVendorKey] != "" {
			t.Errorf("%s metadata sent chassis %q/%q on mobile", name, m[metadataChassisTypeKey], m[metadataChassisVendorKey])
		}
	}
}

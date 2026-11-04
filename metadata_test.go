package ctrld

import (
	"context"
	"reflect"
	"testing"
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

//go:build windows

package cli

import (
	"testing"
	"time"
)

func TestDNSInterceptIgnoredChangeReconcileDueWindowsPreservesImmediateBehavior(t *testing.T) {
	p := &prog{}
	now := time.Now()

	if !p.dnsInterceptIgnoredChangeReconcileDue(now) {
		t.Fatal("first ignored Windows change must reconcile immediately")
	}
	if !p.dnsInterceptIgnoredChangeReconcileDue(now) {
		t.Fatal("Windows ignored changes must not inherit the macOS pf rate limit")
	}
}

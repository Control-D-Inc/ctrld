//go:build darwin

package cli

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestInterceptDNSTargetDHCPDeadline(t *testing.T) {
	if reflect.ValueOf(interceptDHCPNameserversForInterfaceFn).Pointer() != reflect.ValueOf(readTargetDHCPNameservers).Pointer() {
		t.Fatal("target discovery bypasses bounded DHCP reader")
	}
	h := newInterceptTargetHarness(t)
	h.dns["Wi-Fi"] = []string{"192.0.2.53"}
	original := targetDHCPReadFn
	t.Cleanup(func() { targetDHCPReadFn = original })
	entered := make(chan struct{})
	targetDHCPReadFn = func(ctx context.Context, device string) ([]string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > nativeTargetReadBudget || device != "en1" {
			t.Error("missing bounded context or wrong interface")
			close(entered)
			return nil, errors.New("invalid context")
		}
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	interceptDHCPNameserversForInterfaceFn = readTargetDHCPNameservers
	p := newInterceptTargetProg()
	finished := make(chan struct{})
	go func() { p.ensureInterceptDNSTarget([]string{}); close(finished) }()
	<-entered
	cleaned := make(chan struct{})
	go func() { p.removeInterceptDNSTarget("test shutdown"); close(cleaned) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("DHCP lookup did not release reconciliation")
	}
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("cleanup remained blocked after DHCP deadline")
	}
	if !slices.Equal(h.dns["Wi-Fi"], []string{"192.0.2.53"}) || len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
		t.Fatal("deadline changed existing static DNS")
	}
}

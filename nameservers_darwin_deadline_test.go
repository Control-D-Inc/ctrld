//go:build darwin

package ctrld

import (
	"context"
	"errors"
	"testing"
)

func TestDHCPInterfaceContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := DHCPNameserversForInterfaceContext(ctx, "unused-test-interface")
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discovery: got=%v err=%v", got, err)
	}
}

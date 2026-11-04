package ctrld

import (
	"context"
	"testing"
)

func TestNameservers(t *testing.T) {
	ns := nameservers(context.Background())
	if len(ns) == 0 {
		t.Fatal("failed to get nameservers")
	}
	t.Log(ns)
}

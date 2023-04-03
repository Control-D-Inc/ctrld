package ctrld

import "testing"

func TestNameservers(t *testing.T) {
	ns := nameservers()
	if len(ns) == 0 {
		t.Fatal("failed to get nameservers")
	}
	t.Log(ns)
}

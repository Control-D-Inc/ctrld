//go:build darwin

package cli

import (
	"context"
	"testing"
)

func TestAppStoreLocalAPIEndpointsRequireTailscaleSignature(t *testing.T) {
	oldList, oldVerify := listAppStoreProofsFn, verifyTailscaleProcessFn
	t.Cleanup(func() { listAppStoreProofsFn, verifyTailscaleProcessFn = oldList, oldVerify })

	const proof = "/Users/u/Library/Group Containers/W5364U7YZB.io.tailscale.ipn.macos/sameuserproof-"
	listAppStoreProofsFn = func(context.Context) ([]byte, error) {
		return []byte("p100\ncIPNExtension\nn" + proof + "8080-spoof\n" +
			"p200\ncIPNExtension\nn" + proof + "49152-real\n"), nil
	}
	var checked []int
	verifyTailscaleProcessFn = func(_ context.Context, pid int) bool {
		checked = append(checked, pid)
		return pid == 200
	}

	eps := appStoreLocalAPIEndpoints(context.Background())
	if len(eps) != 1 || eps[0].name != "app-store" || eps[0].token != "real" {
		t.Fatalf("endpoints = %+v, want only the signed process", eps)
	}
	if len(checked) != 2 || checked[0] != 100 || checked[1] != 200 {
		t.Fatalf("verified pids = %v, want [100 200]", checked)
	}

	verifyTailscaleProcessFn = func(context.Context, int) bool { return false }
	if eps := appStoreLocalAPIEndpoints(context.Background()); len(eps) != 0 {
		t.Fatalf("endpoints = %+v for unsigned processes, want none", eps)
	}
}

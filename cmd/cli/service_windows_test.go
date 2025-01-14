package cli

import (
	"testing"
	"time"
)

func Test_hasLocalDnsServerRunning(t *testing.T) {
	start := time.Now()
	hasDns := hasLocalDnsServerRunning()
	t.Logf("Using Windows API takes: %d", time.Since(start).Milliseconds())

	start = time.Now()
	hasDnsPowershell := hasLocalDnsServerRunningPowershell()
	t.Logf("Using Powershell takes: %d", time.Since(start).Milliseconds())

	if hasDns != hasDnsPowershell {
		t.Fatalf("result mismatch, want: %v, got: %v", hasDnsPowershell, hasDns)
	}
}

func hasLocalDnsServerRunningPowershell() bool {
	_, err := powershell("Get-Process -Name DNS")
	return err == nil
}

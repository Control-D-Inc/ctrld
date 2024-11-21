package cli

import (
	"fmt"
	"testing"
	"time"
)

func Test_getActiveDirectoryDomain(t *testing.T) {
	start := time.Now()
	domain, err := getActiveDirectoryDomain()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using Windows API takes: %d", time.Since(start).Milliseconds())

	start = time.Now()
	domainPowershell, err := getActiveDirectoryDomainPowershell()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using Powershell takes: %d", time.Since(start).Milliseconds())

	if domain != domainPowershell {
		t.Fatalf("result mismatch, want: %v, got: %v", domainPowershell, domain)
	}
}

func getActiveDirectoryDomainPowershell() (string, error) {
	cmd := "$obj = Get-WmiObject Win32_ComputerSystem; if ($obj.PartOfDomain) { $obj.Domain }"
	output, err := powershell(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get domain name: %w, output:\n\n%s", err, string(output))
	}
	return string(output), nil
}

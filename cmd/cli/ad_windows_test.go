package cli

import (
	"fmt"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/testhelper"
	"github.com/stretchr/testify/assert"
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

func Test_addSplitDnsRule(t *testing.T) {
	newCfg := func(domains ...string) *ctrld.Config {
		cfg := testhelper.SampleConfig(t)
		lc := cfg.Listener["0"]
		for _, domain := range domains {
			lc.Policy.Rules = append(lc.Policy.Rules, ctrld.Rule{domain: []string{}})
		}
		return cfg
	}
	tests := []struct {
		name   string
		cfg    *ctrld.Config
		domain string
		added  bool
	}{
		{"added", newCfg(), "example.com", true},
		{"TLD existed", newCfg("example.com"), "*.example.com", true},
		{"wildcard existed", newCfg("*.example.com"), "example.com", true},
		{"not added TLD", newCfg("example.com", "*.example.com"), "example.com", false},
		{"not added wildcard", newCfg("example.com", "*.example.com"), "*.example.com", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			added := addSplitDnsRule(tc.cfg, tc.domain)
			assert.Equal(t, tc.added, added)
		})
	}
}

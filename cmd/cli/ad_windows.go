package cli

import (
	"fmt"
	"strings"

	"github.com/Control-D-Inc/ctrld"
)

// addExtraSplitDnsRule adds split DNS rule for domain if it's part of active directory.
func addExtraSplitDnsRule(lc *ctrld.ListenerConfig) {
	if lc.Policy == nil {
		lc.Policy = &ctrld.ListenerPolicyConfig{}
	}
	domain, err := getActiveDirectoryDomain()
	if err != nil {
		mainLog.Load().Debug().Msgf("unable to get active directory domain: %v", err)
		return
	}
	if domain == "" {
		mainLog.Load().Debug().Msg("no active directory domain found")
		return
	}
	domainRule := "*." + strings.TrimPrefix(domain, ".")
	for _, rule := range lc.Policy.Rules {
		if _, ok := rule[domainRule]; ok {
			mainLog.Load().Debug().Msg("domain rule already exist")
			return
		}
	}
	mainLog.Load().Debug().Msg("adding active directory domain")
	lc.Policy.Rules = append(lc.Policy.Rules, ctrld.Rule{domainRule: []string{}})
}

// getActiveDirectoryDomain returns AD domain name of this computer.
func getActiveDirectoryDomain() (string, error) {
	cmd := "$obj = Get-WmiObject Win32_ComputerSystem; if ($obj.PartOfDomain) { $obj.Domain }"
	output, err := powershell(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get domain name: %w, output:\n\n%s", err, string(output))
	}
	return string(output), nil
}

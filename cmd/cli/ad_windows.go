package cli

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/microsoft/wmi/pkg/base/host"
	hh "github.com/microsoft/wmi/pkg/hardware/host"

	"github.com/Control-D-Inc/ctrld"
)

// addExtraSplitDnsRule adds split DNS rule for domain if it's part of active directory.
func addExtraSplitDnsRule(cfg *ctrld.Config) bool {
	domain, err := getActiveDirectoryDomain()
	if err != nil {
		mainLog.Load().Debug().Msgf("unable to get active directory domain: %v", err)
		return false
	}
	if domain == "" {
		mainLog.Load().Debug().Msg("no active directory domain found")
		return false
	}
	// Network rules are lowercase during toml config marshaling,
	// lowercase the domain here too for consistency.
	domain = strings.ToLower(domain)
	domainRuleAdded := addSplitDnsRule(cfg, domain)
	wildcardDomainRuleRuleAdded := addSplitDnsRule(cfg, "*."+strings.TrimPrefix(domain, "."))
	return domainRuleAdded || wildcardDomainRuleRuleAdded
}

// addSplitDnsRule adds split-rule for given domain if there's no existed rule.
// The return value indicates whether the split-rule was added or not.
func addSplitDnsRule(cfg *ctrld.Config, domain string) bool {
	for n, lc := range cfg.Listener {
		if lc.Policy == nil {
			lc.Policy = &ctrld.ListenerPolicyConfig{}
		}
		for _, rule := range lc.Policy.Rules {
			if _, ok := rule[domain]; ok {
				mainLog.Load().Debug().Msgf("split-rule %q already existed for listener.%s", domain, n)
				return false
			}
		}
		mainLog.Load().Debug().Msgf("adding split-rule %q for listener.%s", domain, n)
		lc.Policy.Rules = append(lc.Policy.Rules, ctrld.Rule{domain: []string{}})
	}
	return true
}

// getActiveDirectoryDomain returns AD domain name of this computer.
func getActiveDirectoryDomain() (string, error) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	whost := host.NewWmiLocalHost()
	cs, err := hh.GetComputerSystem(whost)
	if err != nil {
		return "", err
	}
	defer cs.Close()
	pod, err := cs.GetPropertyPartOfDomain()
	if err != nil {
		return "", err
	}
	if pod {
		return cs.GetPropertyDomain()
	}
	return "", nil
}

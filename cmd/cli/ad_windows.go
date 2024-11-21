package cli

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

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
	for n, lc := range cfg.Listener {
		if lc.Policy == nil {
			lc.Policy = &ctrld.ListenerPolicyConfig{}
		}
		domainRule := "*." + strings.TrimPrefix(domain, ".")
		for _, rule := range lc.Policy.Rules {
			if _, ok := rule[domainRule]; ok {
				mainLog.Load().Debug().Msgf("domain rule already exist for listener.%s", n)
				return false
			}
		}
		mainLog.Load().Debug().Msgf("adding active directory domain for listener.%s", n)
		lc.Policy.Rules = append(lc.Policy.Rules, ctrld.Rule{domainRule: []string{}})
	}
	return true
}

// getActiveDirectoryDomain returns AD domain name of this computer.
func getActiveDirectoryDomain() (string, error) {
	var domain *uint16
	var status uint32
	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return "", err
	}
	defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	if status == syscall.NetSetupDomainName {
		return windows.UTF16PtrToString(domain), nil
	}
	return "", nil
}

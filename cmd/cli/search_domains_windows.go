package cli

import (
	"fmt"
	"syscall"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/util/dnsname"
)

// searchDomains returns the current search domains config.
func searchDomains() ([]dnsname.FQDN, error) {
	flags := winipcfg.GAAFlagIncludeGateways |
		winipcfg.GAAFlagIncludePrefix

	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_UNSPEC, flags)
	if err != nil {
		return nil, fmt.Errorf("winipcfg.GetAdaptersAddresses: %w", err)
	}

	var sds []dnsname.FQDN
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		// Skip if software loopback or other non-physical types
		// This is to avoid the "Loopback Pseudo-Interface 1" issue we see on windows
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		for a := aa.FirstDNSSuffix; a != nil; a = a.Next {
			d, err := dnsname.ToFQDN(a.String())
			if err != nil {
				mainLog.Load().Debug().Err(err).Msgf("Failed to parse domain: %s", a.String())
				continue
			}
			sds = append(sds, d)
		}
	}
	return sds, nil
}

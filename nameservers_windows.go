package ctrld

import (
	"syscall"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromAdapter}
}

func dnsFromAdapter() []string {
	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways|winipcfg.GAAFlagIncludePrefix)
	if err != nil {
		return nil
	}
	ns := make([]string, 0, len(aas)*2)
	seen := make(map[string]bool)
	addressMap := make(map[string]struct{})
	for _, aa := range aas {
		for a := aa.FirstUnicastAddress; a != nil; a = a.Next {
			addressMap[a.Address.IP().String()] = struct{}{}
		}
	}
	for _, aa := range aas {
		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil || ip.IsLoopback() || seen[ip.String()] {
				continue
			}
			if _, ok := addressMap[ip.String()]; ok {
				continue
			}
			seen[ip.String()] = true
			ns = append(ns, ip.String())
		}
	}
	return ns
}

func nameserversFromResolvconf() []string {
	return nil
}

//go:build unix

package ctrld

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/net/netmon"
)

// localNameservers filters a list of nameserver strings, returning only those
// that are not loopback or local machine IP addresses.
func localNameservers(nss []string, regularIPs, loopbackIPs []netip.Addr) []string {
	var result []string
	seen := make(map[string]bool)

	for _, ns := range nss {
		if ip := net.ParseIP(ns); ip != nil {
			// skip loopback and local IPs
			isLocal := false
			for _, v := range slices.Concat(regularIPs, loopbackIPs) {
				if ip.String() == v.String() {
					isLocal = true
					break
				}
			}
			if !isLocal && !seen[ip.String()] {
				seen[ip.String()] = true
				result = append(result, ip.String())
			}
		}
	}
	return result
}

// dnsFromResolvConf reads usable nameservers from /etc/resolv.conf file.
// A nameserver is usable if it's not one of current machine's IP addresses
// and loopback IP addresses.
func dnsFromResolvConf(_ context.Context) []string {
	const (
		maxRetries    = 10
		retryInterval = 100 * time.Millisecond
	)

	regularIPs, loopbackIPs, _ := netmon.LocalAddresses()

	var dns []string
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryInterval)
		}

		nss := CurrentNameserversFromResolvconf()
		localDNS := localNameservers(nss, regularIPs, loopbackIPs)

		// If we successfully read the file and found nameservers, return them
		if len(localDNS) > 0 {
			return localDNS
		}
	}

	return dns
}

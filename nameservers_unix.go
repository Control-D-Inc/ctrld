//go:build unix

package ctrld

import (
	"net"
	"slices"
	"time"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// currentNameserversFromResolvconf returns the current nameservers set from /etc/resolv.conf file.
func currentNameserversFromResolvconf() []string {
	return resolvconffile.NameServers("")
}

// dnsFromResolvConf reads usable nameservers from /etc/resolv.conf file.
// A nameserver is usable if it's not one of current machine's IP addresses
// and loopback IP addresses.
func dnsFromResolvConf() []string {
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

		nss := resolvconffile.NameServers("")
		var localDNS []string
		seen := make(map[string]bool)

		for _, ns := range nss {
			if ip := net.ParseIP(ns); ip != nil {
				// skip loopback IPs
				for _, v := range slices.Concat(regularIPs, loopbackIPs) {
					ipStr := v.String()
					if ip.String() == ipStr {
						continue
					}
				}
				if !seen[ip.String()] {
					seen[ip.String()] = true
					localDNS = append(localDNS, ip.String())
				}
			}
		}

		// If we successfully read the file and found nameservers, return them
		if len(localDNS) > 0 {
			return localDNS
		}
	}

	return dns
}

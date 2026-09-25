package ctrld

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
)

// Link-local addresses identify a host only within their interface's zone.
// In particular, an unzoned local fe80::1 must not exclude fe80::1%en0.
func scutilLocalAddressKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.IsLinkLocalUnicast() {
		return addr
	}
	return addr.WithZone("")
}

// parseScutilNameservers retains IPv6 zones for the eventual socket dial.
func parseScutilNameservers(output []byte, local []netip.Addr) ([]string, error) {
	excluded := make(map[netip.Addr]bool, len(local))
	for _, addr := range local {
		excluded[scutilLocalAddressKey(addr)] = true
	}
	var servers []string
	seen := make(map[netip.Addr]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ":")
		if !ok || !strings.HasPrefix(key, "nameserver[") {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || excluded[scutilLocalAddressKey(addr)] || seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, addr.String())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

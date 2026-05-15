package ctrld

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld/internal/dns/resolvconffile"
)

const (
	v4RouteFile = "/proc/net/route"
	v6RouteFile = "/proc/net/ipv6_route"
)

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromResolvConf, dns4, dns6, dnsFromSystemdResolver}
}

func dns4(ctx context.Context) []string {
	f, err := os.Open(v4RouteFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dns []string
	seen := make(map[string]bool)
	vis := virtualInterfaces(ctx)
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := bytes.Fields(s.Bytes())
		if len(fields) < 2 {
			continue
		}
		// Skip virtual interfaces.
		if _, ok := vis[string(bytes.TrimSpace(fields[0]))]; ok {
			continue
		}
		gw := make([]byte, net.IPv4len)
		// Third fields is gateway.
		if _, err := hex.Decode(gw, fields[2]); err != nil {
			continue
		}
		ip := net.IPv4(gw[3], gw[2], gw[1], gw[0])
		if ip.Equal(net.IPv4zero) || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		dns = append(dns, ip.String())
	}
	return dns
}

func dns6(ctx context.Context) []string {
	f, err := os.Open(v6RouteFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dns []string
	vis := virtualInterfaces(ctx)
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := bytes.Fields(s.Bytes())
		if len(fields) < 4 {
			continue
		}
		// Skip virtual interfaces.
		if _, ok := vis[string(bytes.TrimSpace(fields[len(fields)-1]))]; ok {
			continue
		}

		gw := make([]byte, net.IPv6len)
		// Fifth fields is gateway.
		if _, err := hex.Decode(gw, fields[4]); err != nil {
			continue
		}
		ip := net.IP(gw)
		if ip.Equal(net.IPv6zero) {
			continue
		}
		dns = append(dns, ip.String())
	}
	return dns
}

func dnsFromSystemdResolver(_ context.Context) []string {
	c, err := resolvconffile.ParseFile("/run/systemd/resolve/resolv.conf")
	if err != nil {
		return nil
	}
	ns := make([]string, 0, len(c.Nameservers))
	for _, nameserver := range c.Nameservers {
		ns = append(ns, nameserver.String())
	}
	return ns
}

// virtualInterfaces returns a map of virtual interfaces on the current machine.
// This reads from /sys/devices/virtual/net to identify virtual network interfaces
// Virtual interfaces should not have DNS configured as they don't represent physical network connections
func virtualInterfaces(ctx context.Context) map[string]struct{} {
	logger := LoggerFromCtx(ctx)
	s := make(map[string]struct{})
	entries, err := os.ReadDir("/sys/devices/virtual/net")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read /sys/devices/virtual/net")
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			s[strings.TrimSpace(entry.Name())] = struct{}{}
		}
	}
	return s
}

// ValidInterfaces returns a set containing non virtual interfaces.
func ValidInterfaces(ctx context.Context) map[string]struct{} {
	m := make(map[string]struct{})
	vis := virtualInterfaces(ctx)
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		if _, existed := vis[i.Name]; existed {
			return
		}
		m[i.Name] = struct{}{}
	})
	// Fallback to default route interface if found nothing.
	if len(m) == 0 {
		defaultRoute, err := netmon.DefaultRoute()
		if err != nil {
			return m
		}
		m[defaultRoute.InterfaceName] = struct{}{}
	}
	return m
}

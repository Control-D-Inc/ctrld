package ctrld

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"strings"

	"github.com/Control-D-Inc/ctrld/internal/dns/resolvconffile"
)

const (
	v4RouteFile = "/proc/net/route"
	v6RouteFile = "/proc/net/ipv6_route"
)

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromResolvConf, dns4, dns6, dnsFromSystemdResolver}
}

func dns4() []string {
	f, err := os.Open(v4RouteFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dns []string
	seen := make(map[string]bool)
	vis := virtualInterfaces()
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
		if vis.contains(string(bytes.TrimSpace(fields[0]))) {
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

func dns6() []string {
	f, err := os.Open(v6RouteFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dns []string
	vis := virtualInterfaces()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := bytes.Fields(s.Bytes())
		if len(fields) < 4 {
			continue
		}
		// Skip virtual interfaces.
		if vis.contains(string(bytes.TrimSpace(fields[len(fields)-1]))) {
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

func dnsFromSystemdResolver() []string {
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

type set map[string]struct{}

func (s *set) add(e string) {
	(*s)[e] = struct{}{}
}

func (s *set) contains(e string) bool {
	_, ok := (*s)[e]
	return ok
}

// virtualInterfaces returns a set of virtual interfaces on current machine.
func virtualInterfaces() set {
	s := make(set)
	entries, _ := os.ReadDir("/sys/devices/virtual/net")
	for _, entry := range entries {
		if entry.IsDir() {
			s.add(strings.TrimSpace(entry.Name()))
		}
	}
	return s
}

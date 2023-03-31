package ctrld

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"

	"github.com/Control-D-Inc/ctrld/internal/dns/resolvconffile"
)

const (
	v4RouteFile = "/proc/net/route"
	v6RouteFile = "/proc/net/ipv6_route"
)

func dnsFns() []dnsFn {
	return []dnsFn{dns4, dns6, dnsFromSystemdResolver}
}

func dns4() []string {
	f, err := os.Open(v4RouteFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var dns []string
	seen := make(map[string]bool)
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
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := bytes.Fields(s.Bytes())
		if len(fields) < 4 {
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

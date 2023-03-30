package ctrld

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
)

const (
	v4RouteFile = "/proc/net/route"
	v6RouteFile = "/proc/net/ipv6_route"
)

func osNameservers() []string {
	ns4 := dns4()
	ns6 := dns6()
	ns := make([]string, len(ns4)+len(ns6))
	ns = append(ns, ns4...)
	ns = append(ns, ns6...)
	return ns
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
		dns = append(dns, net.JoinHostPort(ip.String(), "53"))
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
		dns = append(dns, net.JoinHostPort(ip.String(), "53"))
	}
	return dns
}

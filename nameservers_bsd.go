//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package ctrld

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

func osNameservers() []string {
	var dns []string
	seen := make(map[string]bool)
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	for _, message := range messages {
		message, ok := message.(*route.RouteMessage)
		if !ok {
			continue
		}
		addresses := message.Addrs
		if len(addresses) < 2 {
			continue
		}
		dst, gw := toNetIP(addresses[0]), toNetIP(addresses[1])
		if dst == nil || gw == nil {
			continue
		}
		if gw.IsLoopback() || seen[gw.String()] {
			continue
		}
		if dst.Equal(net.IPv4zero) || dst.Equal(net.IPv6zero) {
			seen[gw.String()] = true
			dns = append(dns, net.JoinHostPort(gw.String(), "53"))
		}
	}
	return dns
}

func toNetIP(addr route.Addr) net.IP {
	switch t := addr.(type) {
	case *route.Inet4Addr:
		return net.IPv4(t.IP[0], t.IP[1], t.IP[2], t.IP[3])
	case *route.Inet6Addr:
		ip := make(net.IP, net.IPv6len)
		copy(ip, t.IP[:])
		return ip
	default:
		return nil
	}
}

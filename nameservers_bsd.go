//go:build dragonfly || freebsd || netbsd || openbsd

package ctrld

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromResolvConf, dnsFromRIB}
}

func dnsFromRIB(_ context.Context) []string {
	var dns []string
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
		if gw.IsLoopback() {
			continue
		}
		if dst.Equal(net.IPv4zero) || dst.Equal(net.IPv6zero) {
			dns = append(dns, gw.String())
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

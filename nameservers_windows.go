package ctrld

import (
	"net"
	"syscall"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"golang.org/x/sys/windows"
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
	do := func(addr windows.SocketAddress) {
		sa, err := addr.Sockaddr.Sockaddr()
		if err != nil {
			return
		}
		var ip net.IP
		switch sa := sa.(type) {
		case *syscall.SockaddrInet4:
			ip = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
		case *syscall.SockaddrInet6:
			ip = make(net.IP, net.IPv6len)
			copy(ip, sa.Addr[:])
			if ip[0] == 0xfe && ip[1] == 0xc0 {
				// Ignore these fec0/10 ones. Windows seems to
				// populate them as defaults on its misc rando
				// interfaces.
				return
			}
		default:
			return

		}
		if ip.IsLoopback() || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		ns = append(ns, ip.String())
	}
	for _, aa := range aas {
		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			do(dns.Address)
		}
		for gw := aa.FirstGatewayAddress; gw != nil; gw = gw.Next {
			do(gw.Address)
		}
	}
	return ns
}

func nameserversFromResolvconf() []string {
	return nil
}

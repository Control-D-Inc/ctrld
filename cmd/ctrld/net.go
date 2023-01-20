package main

import (
	"net"
	"sync"
)

const controldIPv6Test = "ipv6.controld.io"

var (
	stackOnce          sync.Once
	ipv6Enabled        bool
	canListenIPv6Local bool
)

func probeStack() {
	if _, err := net.Dial("tcp6", controldIPv6Test); err == nil {
		ipv6Enabled = true
	}
	if ln, err := net.Listen("tcp6", "[::1]:53"); err == nil {
		ln.Close()
		canListenIPv6Local = true
	}
}

func supportsIPv6() bool {
	stackOnce.Do(probeStack)
	return ipv6Enabled
}

func supportsIPv6ListenLocal() bool {
	stackOnce.Do(probeStack)
	return canListenIPv6Local
}

// isIPv6 checks if the provided IP is v6.
//
//lint:ignore U1000 use in os_windows.go
func isIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil && parsedIP.To16() != nil
}

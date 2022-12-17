package main

import (
	"net"
	"sync"
)

var (
	stackOnce   sync.Once
	ipv6Enabled bool
)

func probeStack() {
	if ln, err := net.Listen("tcp6", "[::]:0"); err == nil {
		ln.Close()
		ipv6Enabled = true
	}
}

func supportsIPv6() bool {
	stackOnce.Do(probeStack)
	return ipv6Enabled
}

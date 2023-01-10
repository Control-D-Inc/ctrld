package main

import (
	"net"
	"sync"
)

const controldIPv6Test = "ipv6.controld.io"

var (
	stackOnce   sync.Once
	ipv6Enabled bool
)

func probeStack() {
	if _, err := net.Dial("tcp6", controldIPv6Test); err == nil {
		ipv6Enabled = true
	}
}

func supportsIPv6() bool {
	stackOnce.Do(probeStack)
	return ipv6Enabled
}

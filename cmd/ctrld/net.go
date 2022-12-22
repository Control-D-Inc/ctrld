package main

import (
	"net"
	"sync"

	"golang.org/x/net/nettest"
)

var (
	stackOnce   sync.Once
	ipv6Enabled bool
)

func probeStack() {
	// TODO(cuonglm): use nettest.SupportsIPv6 once https://github.com/golang/go/issues/57386 fixed.
	if _, err := nettest.RoutedInterface("ip6", net.FlagUp); err == nil {
		ipv6Enabled = true
	}
}

func supportsIPv6() bool {
	stackOnce.Do(probeStack)
	return ipv6Enabled
}

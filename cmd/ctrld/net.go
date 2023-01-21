package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"tailscale.com/logtail/backoff"
)

const (
	controldIPv6Test = "ipv6.controld.io"
	controldIPv4Test = "ipv4.controld.io"
)

var (
	stackOnce          sync.Once
	ipv6Enabled        bool
	canListenIPv6Local bool
	hasNetworkUp       bool
)

func probeStack() {
	logf := func(format string, args ...any) {
		fmt.Printf(format, args...)
	}
	b := backoff.NewBackoff("probeStack", logf, time.Minute)
	for {
		if _, err := net.Dial("tcp", net.JoinHostPort(controldIPv4Test, "80")); err == nil {
			hasNetworkUp = true
			break
		} else {
			b.BackOff(context.Background(), err)
		}
	}
	if _, err := net.Dial("tcp6", net.JoinHostPort(controldIPv6Test, "80")); err == nil {
		ipv6Enabled = true
	}
	if ln, err := net.Listen("tcp6", "[::1]:53"); err == nil {
		ln.Close()
		canListenIPv6Local = true
	}
}

func netUp() bool {
	stackOnce.Do(probeStack)
	return hasNetworkUp
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

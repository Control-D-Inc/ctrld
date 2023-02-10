package net

import (
	"context"
	"net"
	"sync"
	"time"

	"tailscale.com/logtail/backoff"
)

const (
	controldIPv6Test = "ipv6.controld.io"
	controldIPv4Test = "ipv4.controld.io"
	bootstrapDNS     = "76.76.2.0:53"
)

var Dialer = &net.Dialer{
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 10 * time.Second,
			}
			return d.DialContext(ctx, "udp", bootstrapDNS)
		},
	},
}

var (
	stackOnce          sync.Once
	ipv4Enabled        bool
	ipv6Enabled        bool
	canListenIPv6Local bool
	hasNetworkUp       bool
)

func probeStack() {
	b := backoff.NewBackoff("probeStack", func(format string, args ...any) {}, time.Minute)
	for {
		if _, err := Dialer.Dial("udp", bootstrapDNS); err == nil {
			hasNetworkUp = true
			break
		} else {
			b.BackOff(context.Background(), err)
		}
	}
	if _, err := Dialer.Dial("tcp4", net.JoinHostPort(controldIPv4Test, "80")); err == nil {
		ipv4Enabled = true
	}
	if _, err := Dialer.Dial("tcp6", net.JoinHostPort(controldIPv6Test, "80")); err == nil {
		ipv6Enabled = true
	}
	if ln, err := net.Listen("tcp6", "[::1]:53"); err == nil {
		ln.Close()
		canListenIPv6Local = true
	}
}

func Up() bool {
	stackOnce.Do(probeStack)
	return hasNetworkUp
}

func SupportsIPv4() bool {
	stackOnce.Do(probeStack)
	return ipv4Enabled
}

func SupportsIPv6() bool {
	stackOnce.Do(probeStack)
	return ipv6Enabled
}

func SupportsIPv6ListenLocal() bool {
	stackOnce.Do(probeStack)
	return canListenIPv6Local
}

// IsIPv6 checks if the provided IP is v6.
//
//lint:ignore U1000 use in os_windows.go
func IsIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil && parsedIP.To16() != nil
}

package ctrld

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

var (
	hasIPv6Once   sync.Once
	ipv6Available atomic.Bool
)

// HasIPv6 reports whether the current network stack has IPv6 available.
//
// Keep the first call cheap and bounded. It runs on the DNS path (upstream
// transport setup) behind a sync.Once, so every query waits for it, and under
// Windows NRPT it can run after DNS already points at ctrld. v1.5.7 started a
// netmon monitor here; its first interface state runs WinHTTP proxy discovery,
// which needs DNS through this same ctrld, and a --config start stalled for
// about 100 s (docs/known-issues.md). Network monitoring belongs to the one
// monitor that reports through SetIPv6Available.
func HasIPv6() bool {
	hasIPv6Once.Do(func() {
		ProxyLogger.Load().Debug().Msg("checking for IPv6 availability once")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		val := ctrldnet.IPv6Available(ctx)
		ipv6Available.Store(val)
		ProxyLogger.Load().Debug().Msgf("ipv6 availability: %v", val)
	})
	return ipv6Available.Load()
}

// SetIPv6Available stores the IPv6 state that the network monitor reports, so
// one monitor serves the whole process.
func SetIPv6Available(v bool) {
	ipv6Available.Store(v)
}

// DisableIPv6 marks IPv6 as unavailable if enabled.
func DisableIPv6() {
	if ipv6Available.CompareAndSwap(true, false) {
		ProxyLogger.Load().Debug().Msg("turned off IPv6 availability")
	}
}

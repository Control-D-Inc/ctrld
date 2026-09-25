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
func HasIPv6(ctx context.Context) bool {
	hasIPv6Once.Do(func() {
		logger := LoggerFromCtx(ctx)
		logger.Debug().Msg("Checking for ipv6 availability once")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		val := ctrldnet.IPv6Available(ctx)
		ipv6Available.Store(val)
		logger.Debug().Msgf("ipv6 availability: %v", val)
	})
	return ipv6Available.Load()
}

// SetIPv6Available stores the IPv6 state that the network monitor reports, so
// one monitor serves the whole process.
func SetIPv6Available(v bool) {
	ipv6Available.Store(v)
}

// DisableIPv6 marks IPv6 as unavailable if enabled.
func DisableIPv6(ctx context.Context) {
	if ipv6Available.CompareAndSwap(true, false) {
		logger := LoggerFromCtx(ctx)
		logger.Debug().Msg("Turned off ipv6 availability")
	}
}

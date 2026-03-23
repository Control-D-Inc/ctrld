package ctrld

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/netmon"

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
		mon, err := netmon.New(func(format string, args ...any) {})
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to monitor ipv6 state")
			return
		}
		mon.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
			old := ipv6Available.Load()
			cur := delta.Monitor.InterfaceState().HaveV6
			if old != cur {
				logger.Warn().Msgf("ipv6 availability changed, old: %v, new: %v", old, cur)
			} else {
				logger.Debug().Msg("ipv6 availability does not Changed")
			}
			ipv6Available.Store(cur)
		})
		mon.Start()
	})
	return ipv6Available.Load()
}

// DisableIPv6 marks IPv6 as unavailable if enabled.
func DisableIPv6(ctx context.Context) {
	if ipv6Available.CompareAndSwap(true, false) {
		logger := LoggerFromCtx(ctx)
		logger.Debug().Msg("Turned off ipv6 availability")
	}
}

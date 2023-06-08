package ctrld

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/logtail/backoff"

	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

var (
	hasIPv6Once   sync.Once
	ipv6Available atomic.Bool
)

func hasIPv6() bool {
	hasIPv6Once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		val := ctrldnet.IPv6Available(ctx)
		ipv6Available.Store(val)
		go probingIPv6(val)
	})
	return ipv6Available.Load()
}

// TODO(cuonglm): doing poll check natively for supported platforms.
func probingIPv6(old bool) {
	b := backoff.NewBackoff("probingIPv6", func(format string, args ...any) {}, 30*time.Second)
	bCtx := context.Background()
	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cur := ctrldnet.IPv6Available(ctx)
			if ipv6Available.CompareAndSwap(old, cur) {
				old = cur
			}
		}()
		b.BackOff(bCtx, errors.New("no change"))
	}
}

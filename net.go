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

const ipv6ProbingInterval = 10 * time.Second

func hasIPv6() bool {
	hasIPv6Once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		val := ctrldnet.IPv6Available(ctx)
		ipv6Available.Store(val)
		go probingIPv6(context.TODO(), val)
	})
	return ipv6Available.Load()
}

// TODO(cuonglm): doing poll check natively for supported platforms.
func probingIPv6(ctx context.Context, old bool) {
	ticker := time.NewTicker(ipv6ProbingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				cur := ctrldnet.IPv6Available(ctx)
				if ipv6Available.CompareAndSwap(old, cur) {
					old = cur
				}
			}()
		}
	}
}

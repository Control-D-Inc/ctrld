package cli

import (
	"context"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// A query that an encrypted upstream fails falls back to the OS resolver,
// which sends it in plaintext on port 53. After a sleep or a network change,
// that failure is often not the upstream's: the query rode a connection opened
// on the previous network, or before the sleep, and timed out on it. A new
// connection answers at once (#631). So:
//
//   - every query first checks whether the host slept since the previous
//     query, and if so renews the upstream connections before it is sent. A
//     sleep shows on the clocks before netmon or a wake detector reports it.
//   - before the fallback, a failed query is retried once on fresh
//     connections when the network epoch moved while it ran: a network change
//     or a wake was handled, or a sleep was found then, and the renewal gave
//     the retry new transports.

// hostSleepSlack is how far the wall clock may move ahead of the awake clock
// between two checks before the host counts as having slept. The awake
// clock's rate also differs from the NTP-disciplined wall clock, by far less
// than 1%, which the check allows on top.
const hostSleepSlack = 2 * time.Second

// Clocks of the sleep check. Tests replace them.
var (
	sleepWatchWallFn  = func() time.Time { return time.Now().Round(0) }
	sleepWatchAwakeFn = awakeClock
)

// sleepWatch finds a sleep of the host between two of its checks: the wall
// clock keeps running while the host sleeps, and the awake clock does not.
type sleepWatch struct {
	mu    sync.Mutex
	seen  bool
	wall  time.Time
	awake time.Duration
}

// slept reports whether the host slept since the previous call. A wall clock
// step, as from NTP, reads the same, and costs one renewal of the connections.
func (w *sleepWatch) slept() bool {
	wall, awake := sleepWatchWallFn(), sleepWatchAwakeFn()
	w.mu.Lock()
	defer w.mu.Unlock()
	seen, prevWall, prevAwake := w.seen, w.wall, w.awake
	w.seen, w.wall, w.awake = true, wall, awake
	if !seen {
		return false
	}
	awakeFor := awake - prevAwake
	return wall.Sub(prevWall)-awakeFor > hostSleepSlack+awakeFor/100
}

// renewConnectionsIfSlept renews the upstream connections if the host slept
// since the previous check, and reports whether it did.
func (p *prog) renewConnectionsIfSlept(ctx context.Context) bool {
	if !p.sleepWatch.slept() {
		return false
	}
	ctrld.Log(ctx, mainLog.Load().Info(), "host slept since the previous query; renewing upstream connections")
	p.renewUpstreamConnections()
	return true
}

// renewUpstreamConnections makes every upstream open new connections for its
// next query, and moves the network epoch, so queries running on the old
// connections retry on the new ones. The re-bootstrap is lazy: the next query
// builds the transports.
func (p *prog) renewUpstreamConnections() {
	p.connRenewMu.Lock()
	defer p.connRenewMu.Unlock()
	p.renewUpstreamConnectionsLocked()
}

func (p *prog) renewUpstreamConnectionsLocked() {
	if p.cfg != nil {
		for _, uc := range p.cfg.Upstream {
			uc.ReBootstrap()
		}
	}
	// After the re-bootstrap, so a query that sees the new epoch retries on
	// the new transports.
	p.networkEpoch.Add(1)
}

// retryOnFreshConnection reports whether a query whose upstreams all failed
// gets one more try on fresh connections before any fallback. epoch is the
// network epoch before its first try.
func (p *prog) retryOnFreshConnection(ctx context.Context, upstreams []string, configs []*ctrld.UpstreamConfig, epoch uint64) bool {
	// Internal Domain resolvers have their own fallback, and the network
	// resolvers they fall back to are not the plaintext catch-all.
	if p.internalDomainExplicitUpstreams(upstreams) || p.internalDomainFallbackUpstreams(upstreams) {
		return false
	}
	if !hasConnectionUpstream(configs) {
		return false
	}
	// A sleep that no query has seen yet renews the connections, and moves
	// the epoch.
	p.renewConnectionsIfSlept(ctx)
	if p.networkEpoch.Load() == epoch {
		return false
	}
	ctrld.Log(ctx, mainLog.Load().Debug(), "network changed or host slept during the query; retrying upstreams on fresh connections")
	return true
}

// hasConnectionUpstream reports whether any upstream keeps connections that a
// network change can leave dead: DoH, DoH3, DoT and DoQ.
func hasConnectionUpstream(configs []*ctrld.UpstreamConfig) bool {
	for _, uc := range configs {
		if uc == nil {
			continue
		}
		switch uc.Type {
		case ctrld.ResolverTypeDOH, ctrld.ResolverTypeDOH3, ctrld.ResolverTypeDOT, ctrld.ResolverTypeDOQ:
			return true
		}
	}
	return false
}

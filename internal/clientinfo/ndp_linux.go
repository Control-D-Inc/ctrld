package clientinfo

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Resubscription backoff: the delay starts at ndpResubscribeMinDelay and
// doubles up to ndpResubscribeMaxDelay while subscriptions keep failing. A
// subscription that lived for at least ndpResubscribeMaxDelay resets it.
const (
	ndpResubscribeMinDelay = time.Second
	ndpResubscribeMaxDelay = time.Minute
)

// neighWatcher keeps the NDP table up to date from neighbor subscriptions.
// Tests build their own to fake the subscription and shorten the delays.
type neighWatcher struct {
	// subscribe opens a neighbor subscription.
	subscribe func(chan<- netlink.NeighUpdate, <-chan struct{}, netlink.NeighSubscribeOptions) error
	// rescan re-reads the NDP table after a resubscription, to pick up
	// neighbors added while no subscription was open. It only adds entries:
	// a neighbor deleted in that window stays known until it is replaced.
	rescan             func(*ndpDiscover)
	minDelay, maxDelay time.Duration
}

var defaultNeighWatcher = neighWatcher{
	subscribe: netlink.NeighSubscribeWithOptions,
	rescan:    (*ndpDiscover).scan,
	minDelay:  ndpResubscribeMinDelay,
	maxDelay:  ndpResubscribeMaxDelay,
}

// errNeighSubscriptionClosed is reported when the neighbor subscription ends
// without the netlink library reporting why.
var errNeighSubscriptionClosed = errors.New("neighbor subscription closed")

// scan populates NDP table using information from system mappings.
func (nd *ndpDiscover) scan() {
	neighs, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		nd.logger.Warn().Err(err).Msg("Could not get neighbor list")
		return
	}

	for _, n := range neighs {
		// Skipping non-reachable neighbors.
		if n.State&netlink.NUD_REACHABLE == 0 {
			continue
		}
		ip := n.IP.String()
		mac := n.HardwareAddr.String()
		nd.saveInfo(ip, mac)
	}
}

// subscribe watches NDP table changes and update new information to local table.
//
// The netlink library closes the update channel when the subscription fails,
// for example with ENOBUFS after the socket buffer overflowed. subscribe then
// opens a new subscription after a backoff delay and rescans the NDP table for
// neighbors added meanwhile, so it neither spins on the closed channel nor
// silently stops watching.
func (nd *ndpDiscover) subscribe(ctx context.Context) {
	defaultNeighWatcher.run(ctx, nd)
}

// run watches neighbor changes into nd until ctx is done, resubscribing with
// backoff whenever a subscription ends or cannot be opened.
func (w neighWatcher) run(ctx context.Context, nd *ndpDiscover) {
	delay := w.minDelay
	for attempt := 0; ; attempt++ {
		started := time.Now()
		opened, err := w.watch(ctx, nd, attempt > 0)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= w.maxDelay {
			delay = w.minDelay
		}
		if opened {
			nd.logger.Warn().Err(err).Msgf("NDP neighbor subscription ended, resubscribing in %s", delay)
		} else {
			nd.logger.Warn().Err(err).Msgf("Could not subscribe to NDP neighbor changes, retrying in %s", delay)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, w.maxDelay)
	}
}

// watch runs one neighbor subscription into nd until ctx is done or the
// subscription ends, and returns whether the subscription was opened and why
// it ended. When rescan is true, the NDP table is read again once the
// subscription is open.
func (w neighWatcher) watch(ctx context.Context, nd *ndpDiscover, rescan bool) (opened bool, err error) {
	var (
		mu      sync.Mutex
		lastErr error
	)
	ch := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	opts := netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) {
			mu.Lock()
			lastErr = err
			mu.Unlock()
		},
	}
	if err := w.subscribe(ch, done, opts); err != nil {
		close(done)
		return false, err
	}
	defer func() {
		// Closing done closes the socket. Drain ch until the library closes
		// it, so its receive goroutine is not left blocked on a send.
		close(done)
		for range ch {
		}
	}()
	if rescan {
		w.rescan(nd)
	}
	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case nu, ok := <-ch:
			if !ok {
				mu.Lock()
				err := lastErr
				mu.Unlock()
				if err != nil {
					return true, err
				}
				return true, errNeighSubscriptionClosed
			}
			nd.handleNeighUpdate(nu)
		}
	}
}

// handleNeighUpdate applies one neighbor update to the local table.
func (nd *ndpDiscover) handleNeighUpdate(nu netlink.NeighUpdate) {
	if nu.Family != netlink.FAMILY_V6 {
		return
	}
	ip := normalizeIP(nu.IP.String())
	if nu.Type == unix.RTM_DELNEIGH {
		nd.logger.Debug().Msgf("Removing ndp neighbor: %s", ip)
		nd.mac.Delete(ip)
		return
	}
	mac := nu.HardwareAddr.String()
	switch nu.State {
	case netlink.NUD_REACHABLE:
		nd.saveInfo(ip, mac)
	case netlink.NUD_FAILED:
		nd.logger.Debug().Msgf("Removing ndp neighbor with failed state: %s", ip)
		nd.mac.Delete(ip)
	}
}

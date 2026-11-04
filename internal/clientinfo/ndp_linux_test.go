package clientinfo

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Control-D-Inc/ctrld"
)

// fakeSubscription stands in for netlink.NeighSubscribeWithOptions. Like the
// library, it delivers updates from its own goroutine with a send that does
// not watch done, and closes ch when that goroutine ends: after the updates
// when fail is set, reporting fail through the error callback, or once done
// is closed.
type fakeSubscription struct {
	updates    []netlink.NeighUpdate
	fail       error
	beforeSend func(i int, done <-chan struct{}) // called before sending updates[i], if set

	calls  atomic.Int32
	exited chan struct{} // closed when the latest delivery goroutine returns
}

func (f *fakeSubscription) subscribe(ch chan<- netlink.NeighUpdate, done <-chan struct{}, opts netlink.NeighSubscribeOptions) error {
	f.calls.Add(1)
	exited := make(chan struct{})
	f.exited = exited
	go func() {
		defer close(exited)
		defer close(ch)
		for i, u := range f.updates {
			if f.beforeSend != nil {
				f.beforeSend(i, done)
			}
			ch <- u
		}
		if f.fail != nil {
			opts.ErrorCallback(f.fail)
			return
		}
		<-done
	}()
	return nil
}

// testWatcher returns a neighWatcher using subscribe, with short delays and a
// rescan that does nothing.
func testWatcher(subscribe func(chan<- netlink.NeighUpdate, <-chan struct{}, netlink.NeighSubscribeOptions) error) neighWatcher {
	return neighWatcher{
		subscribe: subscribe,
		rescan:    func(*ndpDiscover) {},
		minDelay:  20 * time.Millisecond,
		maxDelay:  80 * time.Millisecond,
	}
}

// neighUpdate builds an IPv6 neighbor update. Each IP gets its own MAC, whose
// last byte is the IP's last byte, since saveInfo moves a MAC between IPs.
func neighUpdate(typ uint16, ip string, state int) netlink.NeighUpdate {
	parsed := net.ParseIP(ip)
	mac := net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, parsed[len(parsed)-1]}
	return netlink.NeighUpdate{Type: typ, Neigh: netlink.Neigh{
		Family:       netlink.FAMILY_V6,
		State:        state,
		IP:           parsed,
		HardwareAddr: mac,
	}}
}

// runWithin runs fn and fails the test if it has not returned within d.
func runWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		fn()
	}()
	select {
	case <-finished:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// TestWatchReturnsWhenSubscriptionCloses is the regression test for
// the busy loop: a closed update channel must end the watch with the
// subscription error instead of being read forever as zero-value updates.
func TestWatchReturnsWhenSubscriptionCloses(t *testing.T) {
	enobufs := unix.ENOBUFS
	fake := &fakeSubscription{
		updates: []netlink.NeighUpdate{neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::1", netlink.NUD_REACHABLE)},
		fail:    enobufs,
	}
	nd := &ndpDiscover{logger: ctrld.NopLogger}
	var (
		opened bool
		err    error
	)
	runWithin(t, 2*time.Second, "watch on a closed subscription", func() {
		opened, err = testWatcher(fake.subscribe).watch(context.Background(), nd, false)
	})
	if !opened || !errors.Is(err, enobufs) {
		t.Errorf("watch = (%v, %v), want (true, %v)", opened, err, enobufs)
	}
	if got := nd.LookupMac("2001:db8::1"); got != "00:11:22:33:44:01" {
		t.Errorf("update before the failure not applied, LookupMac = %q", got)
	}

	// Without an error callback report, the closure itself is the reason.
	silent := testWatcher(func(ch chan<- netlink.NeighUpdate, _ <-chan struct{}, _ netlink.NeighSubscribeOptions) error {
		close(ch)
		return nil
	})
	runWithin(t, 2*time.Second, "watch on a silently closed subscription", func() {
		opened, err = silent.watch(context.Background(), nd, false)
	})
	if !opened || !errors.Is(err, errNeighSubscriptionClosed) {
		t.Errorf("watch = (%v, %v), want (true, %v)", opened, err, errNeighSubscriptionClosed)
	}
}

func TestWatchAppliesUpdatesAndStopsOnCancel(t *testing.T) {
	v4 := neighUpdate(unix.RTM_NEWNEIGH, "192.0.2.1", netlink.NUD_REACHABLE)
	v4.Family = netlink.FAMILY_V4
	fake := &fakeSubscription{updates: []netlink.NeighUpdate{
		neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::1", netlink.NUD_REACHABLE),
		neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::2", netlink.NUD_REACHABLE),
		neighUpdate(unix.RTM_DELNEIGH, "2001:db8::2", netlink.NUD_NONE),
		neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::3", netlink.NUD_REACHABLE),
		neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::3", netlink.NUD_FAILED),
		v4,
		// Sent after the watch stopped: the delivery goroutine must still
		// exit instead of blocking on this send forever.
		neighUpdate(unix.RTM_NEWNEIGH, "2001:db8::4", netlink.NUD_REACHABLE),
	}}

	nd := &ndpDiscover{logger: ctrld.NopLogger}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel before the seventh update, and send it only once the watch has
	// stopped, so nothing but the drain can take it.
	fake.beforeSend = func(i int, done <-chan struct{}) {
		if i == 6 {
			cancel()
			<-done
		}
	}

	var (
		opened bool
		err    error
	)
	runWithin(t, 2*time.Second, "watch after cancellation", func() {
		opened, err = testWatcher(fake.subscribe).watch(ctx, nd, false)
	})
	if !opened || !errors.Is(err, context.Canceled) {
		t.Errorf("watch = (%v, %v), want (true, %v)", opened, err, context.Canceled)
	}
	select {
	case <-fake.exited:
	case <-time.After(2 * time.Second):
		t.Fatal("subscription goroutine leaked after cancellation")
	}

	for ip, want := range map[string]string{
		"2001:db8::1": "00:11:22:33:44:01",
		"2001:db8::2": "", // deleted
		"2001:db8::3": "", // failed
		"192.0.2.1":   "", // not IPv6
	} {
		if got := nd.LookupMac(ip); got != want {
			t.Errorf("LookupMac(%s) = %q, want %q", ip, got, want)
		}
	}
}

func TestRunResubscribesWithBackoffAndRescans(t *testing.T) {
	fake := &fakeSubscription{fail: unix.ENOBUFS}
	var rescans atomic.Int32
	w := testWatcher(fake.subscribe)
	w.rescan = func(*ndpDiscover) { rescans.Add(1) }

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	runWithin(t, 2*time.Second, "run", func() { w.run(ctx, &ndpDiscover{logger: ctrld.NopLogger}) })

	// Delays of 20, 40, 80, 80, ... ms give about 6 subscriptions in 400ms.
	// A retry loop without backoff would make thousands.
	calls := fake.calls.Load()
	if calls < 3 || calls > 10 {
		t.Errorf("subscriptions in 400ms = %d, want 3..10", calls)
	}
	// Every subscription after the first rescans the table.
	if got := rescans.Load(); got != calls-1 {
		t.Errorf("rescans = %d, want %d (one per resubscription)", got, calls-1)
	}
}

func TestRunRetriesSetupFailure(t *testing.T) {
	var calls atomic.Int32
	setupErr := errors.New("netlink unavailable")
	w := testWatcher(func(chan<- netlink.NeighUpdate, <-chan struct{}, netlink.NeighSubscribeOptions) error {
		calls.Add(1)
		return setupErr
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	opened, err := w.watch(context.Background(), &ndpDiscover{logger: ctrld.NopLogger}, false)
	if opened || !errors.Is(err, setupErr) {
		t.Errorf("watch = (%v, %v), want (false, %v)", opened, err, setupErr)
	}

	calls.Store(0)
	runWithin(t, 2*time.Second, "run", func() { w.run(ctx, &ndpDiscover{logger: ctrld.NopLogger}) })
	if got := calls.Load(); got < 2 || got > 8 {
		t.Errorf("setup attempts in 200ms = %d, want 2..8", got)
	}
}

func TestRunStopsPromptlyDuringBackoff(t *testing.T) {
	fake := &fakeSubscription{fail: unix.ENOBUFS}
	w := testWatcher(fake.subscribe)
	w.minDelay, w.maxDelay = time.Hour, time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for fake.calls.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // let the first subscription fail
		cancel()
	}()
	runWithin(t, 2*time.Second, "run cancelled during backoff", func() { w.run(ctx, &ndpDiscover{logger: ctrld.NopLogger}) })
	if got := fake.calls.Load(); got != 1 {
		t.Errorf("subscriptions = %d, want 1", got)
	}
}

// TestWatchRealSubscriptionStops runs the watch on a real kernel neighbor
// subscription. Cancelling must close the socket and end the library's
// receive goroutine: watch only returns once that
// goroutine has closed the channel.
func TestWatchRealSubscriptionStops(t *testing.T) {
	ch := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	if err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{}); err != nil {
		t.Skipf("neighbor subscription unavailable: %v", err)
	}
	close(done)
	for range ch {
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	var (
		opened bool
		err    error
	)
	runWithin(t, 5*time.Second, "watch on a real subscription", func() {
		opened, err = defaultNeighWatcher.watch(ctx, &ndpDiscover{logger: ctrld.NopLogger}, false)
	})
	if !opened || !errors.Is(err, context.Canceled) {
		t.Errorf("watch = (%v, %v), want (true, %v)", opened, err, context.Canceled)
	}
}

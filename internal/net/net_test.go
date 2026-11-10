package net

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestIsUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"enetunreach", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}, true},
		{"ehostunreach", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, true},
		{"windows enetunreach", &net.OpError{Op: "dial", Net: "tcp", Err: windowsENETUNREACH}, true},
		{"windows ehostunreach", &net.OpError{Op: "dial", Net: "tcp", Err: windowsEHOSTUNREACH}, true},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"not an opError", syscall.ENETUNREACH, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnreachable(tc.err); got != tc.want {
				t.Errorf("IsUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestUnreachableTracker(t *testing.T) {
	tr := &unreachableTracker{entries: make(map[string]unreachableEntry)}
	const addr = "[2606:1a40::22]:443"
	now := time.Unix(0, 0)

	// Not suppressed before any failure.
	if tr.suppressed(addr, now) {
		t.Fatal("addr suppressed before any failure")
	}

	// First failure suppresses for the base window.
	tr.markUnreachable(addr, now)
	if !tr.suppressed(addr, now.Add(unreachableBackoffBase-time.Millisecond)) {
		t.Fatal("addr not suppressed within base backoff window")
	}
	if tr.suppressed(addr, now.Add(unreachableBackoffBase)) {
		t.Fatal("addr still suppressed at end of base backoff window")
	}

	// Backoff grows exponentially and is capped at the max.
	tr.markUnreachable(addr, now)
	if got := tr.entries[addr].backoff; got != 2*unreachableBackoffBase {
		t.Fatalf("backoff after second failure = %v, want %v", got, 2*unreachableBackoffBase)
	}
	for i := 0; i < 10; i++ {
		tr.markUnreachable(addr, now)
	}
	if got := tr.entries[addr].backoff; got != unreachableBackoffMax {
		t.Fatalf("backoff not capped: got %v, want %v", got, unreachableBackoffMax)
	}

	// A successful dial clears suppression entirely.
	tr.markReachable(addr)
	if tr.suppressed(addr, now) {
		t.Fatal("addr still suppressed after markReachable")
	}
	if _, ok := tr.entries[addr]; ok {
		t.Fatal("entry not removed after markReachable")
	}
}

func TestProbeStackTimeout(t *testing.T) {
	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		hasV6, port := supportIPv6(context.Background())
		if hasV6 {
			t.Logf("connect to port %s using ipv6: %v", port, hasV6)
		} else {
			t.Log("ipv6 is not available")
		}
	}()

	<-started
	select {
	case <-time.After(probeStackTimeout + time.Second):
		t.Error("probeStack timeout is not enforce")
	case <-done:
	}
}

// stubProbeDial replaces the network probe and forgets an earlier probe.
func stubProbeDial(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	reset := func() {
		stackMu.Lock()
		stackProbed, hasNetworkUp, canListenIPv6Local = false, false, false
		stackMu.Unlock()
	}
	oldDial := probeStackDial
	probeStackDial = dial
	reset()
	t.Cleanup(func() { probeStackDial = oldDial; reset() })
}

func TestUpUntilStopsWithoutNetwork(t *testing.T) {
	stubProbeDial(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("network is down")
	})
	stopCh := make(chan struct{})
	result := make(chan bool, 1)
	go func() { result <- UpUntil(stopCh) }()
	close(stopCh)
	select {
	case up := <-result:
		if up {
			t.Fatal("UpUntil reported the network up while it was down")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpUntil did not stop after the stop channel closed")
	}

	// A probe that a stop cut short must not become the cached answer. Only
	// the dial changes here: the state of the stopped probe stays.
	probeStackDial = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	if !UpUntil(nil) {
		t.Fatal("a stopped probe was kept as the network state")
	}
}

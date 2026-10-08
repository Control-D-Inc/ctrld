//go:build windows

package cli

import (
	"errors"
	"testing"
)

// TestStaleCleanupRequiresPositiveEvidence pins the guard that protects a live
// pre-session-scoped ctrld service.
//
// ctrldServiceLiveness cannot answer for an unreachable SCM, a caller without rights, or a
// service mid-stop. Folding those into "stopped" would let a hand-run "ctrld run" delete
// the sublayer of a live old-build service - the exact enforcement strip the interactive
// guard exists to prevent - because that build's non-dynamic sublayer looks like an
// orphan. Only a positive stopped answer may unlock the cleanup.
func TestStaleCleanupRequiresPositiveEvidence(t *testing.T) {
	tests := []struct {
		name        string
		interactive bool
		liveness    serviceLiveness
		want        bool
	}{
		// A service start is the deadlock case: nothing of ctrld's is live yet, and this
		// is the only path that can break a host locked out by orphaned filters.
		{"service start with a running service", false, serviceLivenessRunning, true},
		{"service start with an unknown state", false, serviceLivenessUnknown, true},
		{"service start with a stopped service", false, serviceLivenessStopped, true},

		// Interactive: only positive evidence of absence unlocks it.
		{"ctrld run alongside a live service", true, serviceLivenessRunning, false},
		{"ctrld run when the SCM cannot be queried", true, serviceLivenessUnknown, false},
		{"ctrld run with the service stopped or absent", true, serviceLivenessStopped, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := staleCleanupAllowed(tc.interactive, tc.liveness); got != tc.want {
				t.Errorf("staleCleanupAllowed(%v, %v) = %v, want %v", tc.interactive, tc.liveness, got, tc.want)
			}
		})
	}

	// The zero value must be the safe one: a serviceLiveness that was never assigned - a
	// future code path that forgets to set it - must not read as "nothing is live".
	if staleCleanupAllowed(true, serviceLiveness(0)) {
		t.Error("the zero serviceLiveness must not unlock the cleanup: an unset value is not evidence of absence")
	}
}

// stubStaleCleanup installs fakes for the cleanup's guard inputs and for the deletion
// itself, and returns a pointer to the delete-attempt count.
//
// The delete is a WFP syscall: running it for real would remove live filters from the
// machine running the tests, so the assertion has to be made against a substituted delete.
func stubStaleCleanup(t *testing.T, elevated bool, elevErr error, interactive bool, liveness serviceLiveness) *int {
	t.Helper()
	oldElev, oldInter, oldLive, oldDel := staleCleanupElevatedFn, staleCleanupInteractiveFn, staleCleanupLivenessFn, deleteStaleWFPSublayerFn
	t.Cleanup(func() {
		staleCleanupElevatedFn = oldElev
		staleCleanupInteractiveFn = oldInter
		staleCleanupLivenessFn = oldLive
		deleteStaleWFPSublayerFn = oldDel
	})

	deletes := 0
	staleCleanupElevatedFn = func() (bool, error) { return elevated, elevErr }
	staleCleanupInteractiveFn = func() bool { return interactive }
	staleCleanupLivenessFn = func() serviceLiveness { return liveness }
	deleteStaleWFPSublayerFn = func() { deletes++ }
	return &deletes
}

// TestCleanupStaleStateConsultsTheGuardBeforeDeleting is the caller-level half of the
// guard's coverage.
//
// staleCleanupAllowed being correct proves nothing on its own: cleanupStaleDNSInterceptState
// could stop calling it, or call it and delete anyway, and a predicate-only test would stay
// green while a hand-run "ctrld run" stripped a live service's enforcement. This asserts on
// the deletion itself - whether the WFP delete is attempted at all - which is the behaviour
// that matters.
func TestCleanupStaleStateConsultsTheGuardBeforeDeleting(t *testing.T) {
	tests := []struct {
		name        string
		elevated    bool
		elevErr     error
		interactive bool
		liveness    serviceLiveness
		wantDeletes int
	}{
		{
			// The deadlock case this function exists for: a service start, where nothing
			// of ctrld's is live and the host may be carrying orphaned block-all filters.
			name:        "service start attempts the delete",
			elevated:    true,
			wantDeletes: 1,
		},
		{
			// A service start does not consult the SCM at all, so a running service
			// reported here must not change the outcome.
			name:        "service start is not gated on service state",
			elevated:    true,
			liveness:    serviceLivenessRunning,
			wantDeletes: 1,
		},
		{
			name:        "interactive run with a stopped service attempts the delete",
			elevated:    true,
			interactive: true,
			liveness:    serviceLivenessStopped,
			wantDeletes: 1,
		},
		{
			// Deleting here would strip a live pre-session-scoped service's enforcement.
			name:        "interactive run beside a live service does not delete",
			elevated:    true,
			interactive: true,
			liveness:    serviceLivenessRunning,
		},
		{
			// The concern this test was added for: "could not tell" is not absence.
			name:        "interactive run with an unreadable SCM does not delete",
			elevated:    true,
			interactive: true,
			liveness:    serviceLivenessUnknown,
		},
		{
			// Elevation is the only barrier between an unprivileged local process and a
			// path that opens a WFP engine and deletes ctrld's sublayer.
			name:     "an unelevated caller does not delete",
			elevated: false,
		},
		{
			name:    "an elevation check that fails does not delete",
			elevErr: errors.New("cannot determine privilege"),
		},
		{
			// Elevation reported true alongside an error is not a yes.
			name:     "an inconclusive elevation check does not delete",
			elevated: true,
			elevErr:  errors.New("cannot determine privilege"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deletes := stubStaleCleanup(t, tc.elevated, tc.elevErr, tc.interactive, tc.liveness)

			cleanupStaleDNSInterceptState()

			if *deletes != tc.wantDeletes {
				t.Errorf("WFP delete attempts = %d, want %d", *deletes, tc.wantDeletes)
			}
		})
	}
}

// TestCleanupStaleStateDoesNotQueryTheSCMOnAServiceStart pins the ordering the deadlock
// recovery depends on.
//
// The cleanup runs before the network-up wait and before API preflight, on the path a
// locked-out host has to take. Consulting the SCM there would make the one case this
// exists for depend on a query that can block or fail - and a failure answers Unknown,
// which refuses the cleanup. A service start must not ask.
func TestCleanupStaleStateDoesNotQueryTheSCMOnAServiceStart(t *testing.T) {
	deletes := stubStaleCleanup(t, true, nil, false, serviceLivenessStopped)
	queried := false
	staleCleanupLivenessFn = func() serviceLiveness {
		queried = true
		return serviceLivenessRunning
	}

	cleanupStaleDNSInterceptState()

	if queried {
		t.Error("a service start queried the SCM: an unreadable SCM would then refuse the cleanup the locked-out host needs")
	}
	if *deletes != 1 {
		t.Errorf("WFP delete attempts = %d, want 1", *deletes)
	}
}

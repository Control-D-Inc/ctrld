package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"

	"github.com/Control-D-Inc/ctrld"
)

// dnsTargetDecisionDiagnostic keeps one outstanding discovery failure, not a
// history keyed by interface or recovery generation. The target mutex serializes
// access. Correlation IDs are sampled before discovery, never after a slow read.
// A successful read (including empty DNS) closes the failure; it does not claim
// that a subsequent DNS write succeeded. repeat_count counts suppressed reads
// across the whole failure episode, including condition changes; first retains
// its original correlation IDs until discovery succeeds. ID changes alone do
// not reopen the condition or turn periodic reconciliation into a log flood.
type dnsTargetDecisionDiagnostic struct {
	pending   bool
	condition dnsTargetFailureCondition
	first     dnsTargetDecisionContext
	repeats   uint64
}

type dnsTargetOwnership struct {
	service string
	value   string
}

type dnsTargetDecisionContext struct {
	iface        string
	service      string
	ownership    dnsTargetOwnership
	generation   uint64
	transitionID uint64
}

type dnsTargetFailureCondition struct {
	iface     string
	service   string
	ownership dnsTargetOwnership
	stage     string
	class     string
}

// dnsTargetReadErrorClass deliberately never serializes command output or error
// text. Classify wrapped causes by type; unknown errors remain read_failed and
// must never be guessed to mean "no DNS".
func dnsTargetReadErrorClass(err error) string {
	var networkError net.Error
	var exitError *exec.ExitError
	switch {
	case err == nil:
		return "unavailable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.As(err, &exitError):
		return "command_failed"
	default:
		return "read_failed"
	}
}

func dnsTargetDecisionEvent(e *ctrld.LogEvent, c dnsTargetDecisionContext, after dnsTargetOwnership) *ctrld.LogEvent {
	action := "unchanged"
	if c.ownership != after {
		switch {
		case after.service == "":
			action = "removed"
		case c.ownership.service == "":
			action = "set"
		default:
			action = "changed"
		}
	}
	return journal(e).Str("interface", c.iface).Str("service", c.service).
		Uint64("recovery_generation", c.generation).Uint64("transition_id", c.transitionID).
		Str("action", action).
		Bool("ownership_before", c.ownership.service != "").Bool("ownership_after", after.service != "").
		Str("owned_service_before", c.ownership.service).Str("owned_service_after", after.service).
		Str("target_before", c.ownership.value).Str("target_after", after.value)
}

func (d *dnsTargetDecisionDiagnostic) failed(c dnsTargetDecisionContext, stage string, err error) {
	if d == nil {
		return
	}
	condition := dnsTargetFailureCondition{c.iface, c.service, c.ownership, stage, dnsTargetReadErrorClass(err)}
	if d.pending && d.condition == condition {
		// Saturate rather than wrap during an arbitrarily long failure.
		if d.repeats != ^uint64(0) {
			d.repeats++
		}
		return
	}
	if !d.pending {
		d.first = c
	}
	d.pending = true
	d.condition = condition
	dnsTargetDecisionEvent(mainLog.Load().Warn(), c, c.ownership).
		Str("outcome", "discovery_failed").Str("stage", stage).Str("error_class", condition.class).
		Uint64("repeat_count", d.repeats).
		Uint64("failure_recovery_generation", d.first.generation).Uint64("failure_transition_id", d.first.transitionID).
		Msg("intercept DNS target: decision unavailable; DNS unchanged")
}

func (d *dnsTargetDecisionDiagnostic) resolved(c dnsTargetDecisionContext, after dnsTargetOwnership, reason string) {
	if d == nil || !d.pending {
		return
	}
	dnsTargetDecisionEvent(mainLog.Load().Info(), c, after).
		Str("outcome", "decision_available").Str("reason", reason).
		Str("stage", d.condition.stage).Str("error_class", d.condition.class).
		Uint64("repeat_count", d.repeats).
		Uint64("failure_recovery_generation", d.first.generation).Uint64("failure_transition_id", d.first.transitionID).
		Msg("intercept DNS target: decision available again")
	*d = dnsTargetDecisionDiagnostic{}
}

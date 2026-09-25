package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	dnsTargetFailedMessage   = "intercept DNS target: decision unavailable; DNS unchanged"
	dnsTargetResolvedMessage = "intercept DNS target: decision available again"
)

func TestDNSTargetReadErrorClass(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"missing", nil, "unavailable"},
		{"deadline", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "timeout"},
		{"canceled", context.Canceled, "canceled"},
		{"permission", &os.PathError{Op: "read", Path: "private", Err: os.ErrPermission}, "permission_denied"},
		{"command", &exec.ExitError{}, "command_failed"},
		{"wrapped command", fmt.Errorf("wrapped: %w", &exec.ExitError{}), "command_failed"},
		{"untyped error", errors.New("exit status 1"), "read_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsTargetReadErrorClass(tc.err); got != tc.want {
				t.Fatalf("class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDNSTargetDiagnosticFailureAndResolution(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprintf("owned=%t", owned), func(t *testing.T) {
			logs := captureDebugMainLog(t)
			d := dnsTargetDecisionDiagnostic{}
			c := dnsTargetDecisionContext{iface: "en1", service: "Wi-Fi", generation: 3, transitionID: 7}
			if owned {
				c.ownership = dnsTargetOwnership{"Wi-Fi", "127.0.0.53"}
			}
			// A healthy pass must not turn the watchdog into a journal heartbeat.
			d.resolved(c, c.ownership, "dns_less_network")
			failure := errors.New("private.example must not be retained")
			d.failed(c, "dhcp_dns", failure)
			for range 100 {
				c.generation++
				c.transitionID++
				d.failed(c, "dhcp_dns", failure)
			}
			failed := oneRecoveryEvent(t, logs, dnsTargetFailedMessage)
			wantField(t, failed, "journal", true)
			wantField(t, failed, "level", "warn")
			wantField(t, failed, "interface", "en1")
			wantField(t, failed, "service", "Wi-Fi")
			wantField(t, failed, "stage", "dhcp_dns")
			wantField(t, failed, "error_class", "read_failed")
			wantField(t, failed, "action", "unchanged")
			wantField(t, failed, "ownership_before", owned)
			wantField(t, failed, "ownership_after", owned)
			wantField(t, failed, "recovery_generation", float64(3))
			wantField(t, failed, "transition_id", float64(7))
			d.resolved(c, c.ownership, "dns_less_network")
			d.resolved(c, c.ownership, "dns_less_network")
			resolved := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
			wantField(t, resolved, "journal", true)
			wantField(t, resolved, "level", "info")
			wantField(t, resolved, "repeat_count", float64(100))
			wantField(t, resolved, "failure_recovery_generation", float64(3))
			wantField(t, resolved, "failure_transition_id", float64(7))
			wantField(t, resolved, "recovery_generation", float64(103))
			wantField(t, resolved, "transition_id", float64(107))
			if strings.Contains(logs.String(), "private.example") {
				t.Fatal("raw read error leaked into diagnostics")
			}
			if d != (dnsTargetDecisionDiagnostic{}) {
				t.Fatal("resolved diagnostic retained failure state")
			}
			if len(jsonLogEvents(t, logs, "")) != 2 {
				t.Fatal("repeated failures or healthy decisions were logged")
			}
		})
	}
}

func TestDNSTargetDiagnosticConditionChanges(t *testing.T) {
	for _, change := range []string{"interface", "service", "ownership", "stage", "class"} {
		t.Run(change, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			d := dnsTargetDecisionDiagnostic{}
			c := dnsTargetDecisionContext{iface: "en1", service: "Wi-Fi"}
			err := errors.New("read failed")
			stage := "dhcp_dns"
			d.failed(c, stage, err)
			d.failed(c, stage, err)
			switch change {
			case "interface":
				c.iface = "en2"
			case "service":
				c.service = "USB"
			case "ownership":
				c.ownership = dnsTargetOwnership{"USB", "127.0.0.53"}
			case "stage":
				stage = "static_dns"
			case "class":
				err = context.DeadlineExceeded
			}
			d.failed(c, stage, err)
			d.failed(c, stage, err)
			if got := len(jsonLogEvents(t, logs, dnsTargetFailedMessage)); got != 2 {
				t.Fatalf("condition-change failures = %d, want 2", got)
			}
			d.resolved(c, dnsTargetOwnership{}, "dhcp_ipv4_dns")
			wantField(t, oneRecoveryEvent(t, logs, dnsTargetResolvedMessage), "repeat_count", float64(2))
			// A new episode must log again and reset the suppressed count.
			d.failed(c, stage, err)
			if d.repeats != 0 {
				t.Fatal("new episode retained old repeat count")
			}
		})
	}
}

func TestDNSTargetDiagnosticRepeatCountSaturates(t *testing.T) {
	captureDebugMainLog(t)
	d := dnsTargetDecisionDiagnostic{}
	c := dnsTargetDecisionContext{}
	d.failed(c, "dhcp_dns", nil)
	d.repeats = ^uint64(0)
	d.failed(c, "dhcp_dns", nil)
	if d.repeats != ^uint64(0) {
		t.Fatal("repeat count wrapped")
	}
}

func TestDNSTargetDiagnosticOwnershipActions(t *testing.T) {
	owned := dnsTargetOwnership{"Wi-Fi", "127.0.0.53"}
	for _, tc := range []struct {
		action        string
		before, after dnsTargetOwnership
	}{
		{"set", dnsTargetOwnership{}, owned},
		{"removed", owned, dnsTargetOwnership{}},
		{"changed", owned, dnsTargetOwnership{"USB", "127.0.0.53"}},
		{"unchanged", owned, owned},
	} {
		t.Run(tc.action, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			d := dnsTargetDecisionDiagnostic{}
			c := dnsTargetDecisionContext{ownership: tc.before}
			d.failed(c, "dhcp_dns", os.ErrPermission)
			d.resolved(c, tc.after, "dns_less_network")
			event := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
			wantField(t, event, "action", tc.action)
			wantField(t, event, "owned_service_before", tc.before.service)
			wantField(t, event, "owned_service_after", tc.after.service)
			wantField(t, event, "target_before", tc.before.value)
			wantField(t, event, "target_after", tc.after.value)
		})
	}
}

func TestDNSTargetDiagnosticSurvivesDebugTruncation(t *testing.T) {
	p, _ := startInternalLogging(t)
	useTestSendBudget(t, 1024)
	d := dnsTargetDecisionDiagnostic{}
	c := dnsTargetDecisionContext{iface: "en1", service: "Wi-Fi"}
	d.failed(c, "dhcp_dns", errors.New("private.example"))
	for range 5 {
		d.failed(c, "dhcp_dns", errors.New("private.example"))
	}
	d.resolved(c, dnsTargetOwnership{"Wi-Fi", "127.0.0.53"}, "dns_less_network")
	for range 40 {
		mainLog.Load().Debug().Msg(strings.Repeat("debug filler", 20))
	}
	start := time.Now()
	debugPart, journalPart := splitUpload(t, readLogReader(t, p, false), start)
	for _, message := range []string{dnsTargetFailedMessage, dnsTargetResolvedMessage} {
		if strings.Contains(string(debugPart), message) {
			t.Fatalf("fixture did not truncate %q from debug", message)
		}
		if strings.Count(string(journalPart), message) != 1 {
			t.Fatalf("journal did not retain exactly one %q", message)
		}
	}
	if !strings.Contains(string(journalPart), `"repeat_count":5`) {
		t.Fatal("journal lost repeat count")
	}
	if strings.Contains(string(journalPart), "private.example") {
		t.Fatal("raw error leaked into journal")
	}
}

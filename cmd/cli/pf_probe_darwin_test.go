//go:build darwin

package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPFProbeDefaultCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newPFProbeCommand(ctx, "192.0.2.1", "0102")
	if !reflect.DeepEqual(cmd.Args, []string{os.Args[0], "pf-probe-send", "192.0.2.1", "0102"}) {
		t.Fatalf("args=%q", cmd.Args)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("missing credentials")
	}
	cred := cmd.SysProcAttr.Credential
	if cred.Uid != 0 || cred.Gid != 0 || cred.NoSetGroups || len(cred.Groups) != 0 {
		t.Fatalf("unexpected credentials: %+v", cred)
	}
	if cmd.Cancel == nil {
		t.Fatal("command is not context-bound")
	}
	// Do not start this command: credential changes require native privileged QA.
}

func TestPFProbeMonitorIndeterminateContinues(t *testing.T) {
	oldProbe, oldReload, oldDelays := probePFInterceptFn, forceReloadPFInterceptFn, pfInterceptMonitorDelays
	t.Cleanup(func() {
		probePFInterceptFn, forceReloadPFInterceptFn, pfInterceptMonitorDelays = oldProbe, oldReload, oldDelays
	})
	pfInterceptMonitorDelays = []time.Duration{0, 0, 0}
	probes, reloads := 0, 0
	probePFInterceptFn = func(*prog) pfProbeObservation {
		probes++
		if probes == 2 {
			return pfProbeObservation{result: pfProbeIntercepted}
		}
		return pfProbeObservation{stage: "dial", code: "unreachable"}
	}
	forceReloadPFInterceptFn = func(*prog) bool { reloads++; return true }
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}})
	p.pfInterceptMonitor()
	if probes != 3 || reloads != 0 || p.pfMonitorRunning.Load() {
		t.Fatalf("probes=%d reloads=%d owner=%v", probes, reloads, p.pfMonitorRunning.Load())
	}
}

func TestPFProbeRepairCorrelation(t *testing.T) {
	for _, caller := range []string{"post_stabilization", "post_wake", "watchdog", "monitor"} {
		for _, performed := range []bool{false, true} {
			t.Run(caller+"/"+map[bool]string{false: "not_run", true: "completed"}[performed], func(t *testing.T) {
				oldProbe, oldReload, oldDelays := probePFInterceptFn, forceReloadPFInterceptFn, pfInterceptMonitorDelays
				t.Cleanup(func() {
					probePFInterceptFn, forceReloadPFInterceptFn, pfInterceptMonitorDelays = oldProbe, oldReload, oldDelays
				})
				logs := captureTransitionLogs(t)
				stubWakeProbeSchedule(t, 1)
				pfInterceptMonitorDelays = []time.Duration{0}
				p := sourceTestProg(&prog{dnsInterceptState: &pfState{}, stopCh: make(chan struct{})})
				probes, reloads := 0, 0
				probePFInterceptFn = func(*prog) pfProbeObservation {
					probes++
					if probes == 1 {
						return pfProbeObservation{result: pfProbeNotIntercepted, probeID: "cause-probe", recoveryGeneration: 7, stage: "delivery", code: "timeout", target: "192.0.2.1:53"}
					}
					return pfProbeObservation{result: pfProbeIndeterminate, probeID: "confirmation-probe", recoveryGeneration: 8, stage: "dial", code: "unreachable"}
				}
				forceReloadPFInterceptFn = func(*prog) bool { reloads++; p.recoveryGen.Store(99); return performed }
				switch caller {
				case "post_stabilization":
					p.verifyInterceptAfterStabilization()
				case "post_wake":
					p.runWakeProbeAttempt(0, 0)
				case "watchdog":
					p.checkPFWatchdogProbe(pfAnchorCheckIntact)
				case "monitor":
					p.pfInterceptMonitor()
				}
				expected := "not_run"
				if performed {
					expected = "reload_completed"
				}
				found, confirmation := false, false
				for _, line := range strings.Split(logs.String(), "\n") {
					var event map[string]interface{}
					if json.Unmarshal([]byte(line), &event) != nil || event["message"] != "PF repair" {
						continue
					}
					if event["probe_id"] != "cause-probe" || event["recovery_generation"] != float64(7) || event["caller"] != caller {
						t.Fatalf("lost cause: %v", event)
					}
					if event["outcome"] == expected {
						found = true
					}
					if event["outcome"] == "indeterminate" && event["confirmation_probe_id"] == "confirmation-probe" {
						confirmation = true
					}
				}
				if reloads != 1 || !found {
					t.Fatalf("reloads=%d outcome found=%v", reloads, found)
				}
				if performed && caller != "watchdog" && !confirmation {
					t.Fatal("missing confirmation outcome")
				}
			})
		}
	}
}

func TestPFProbeMissingTargetLogTransitions(t *testing.T) {
	logs := captureTransitionLogs(t)
	old := pfProbeNameservers
	t.Cleanup(func() { pfProbeNameservers = old; pfProbeLogs = pfProbeLogState{} })
	pfProbeLogs = pfProbeLogState{}
	first := "[fe80::1%en0]:53"
	pfProbeNameservers = func() []string { return []string{first, "76.76.2.0:53"} }
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}})
	p.probePFIntercept()
	p.probePFIntercept()
	first = "127.0.0.1:53"
	p.probePFIntercept()
	var levels []string
	for _, line := range strings.Split(logs.String(), "\n") {
		var event map[string]interface{}
		if json.Unmarshal([]byte(line), &event) != nil || event["message"] != "DNS intercept probe result" {
			continue
		}
		levels = append(levels, event["level"].(string))
		if len(levels) == 3 && event["repeated_results"] != float64(1) {
			t.Fatal("missing suppressed count")
		}
	}
	if !reflect.DeepEqual(levels, []string{"warn", "debug", "warn"}) {
		t.Fatalf("levels=%v", levels)
	}
}

func TestPFProbeUnsentDoesNotReload(t *testing.T) {
	logs := captureTransitionLogs(t)
	oldServers, oldCommand, oldReload := pfProbeNameservers, newPFProbeCommand, forceReloadPFInterceptFn
	t.Cleanup(func() {
		pfProbeNameservers, newPFProbeCommand, forceReloadPFInterceptFn = oldServers, oldCommand, oldReload
	})
	pfProbeNameservers = func() []string { return []string{"192.0.2.1:53"} }
	newPFProbeCommand = func(ctx context.Context, host, packet string) *exec.Cmd { return pfProbeTestCommand(ctx, "dial") }
	reloads := 0
	forceReloadPFInterceptFn = func(*prog) bool { reloads++; return true }
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}, stopCh: make(chan struct{})})
	if got := p.checkPFWatchdogProbe(pfAnchorCheckIntact); got != pfAnchorCheckDeferred {
		t.Fatalf("watchdog result=%v", got)
	}
	p.verifyInterceptAfterStabilization()
	stubWakeProbeSchedule(t, 1)
	if restored, repaired := p.runWakeProbeAttempt(0, 0); restored || repaired {
		t.Fatalf("unsent wake probe: restored=%v repaired=%v", restored, repaired)
	}
	if reloads != 0 {
		t.Fatalf("unsent probes caused %d reloads", reloads)
	}
	output := logs.String()
	for _, field := range []string{`"probe_id":`, `"recovery_generation":`, `"resolver_target":"192.0.2.1:53"`, `"stage":"dial"`, `"error_code":"unreachable"`, `"outcome":"indeterminate"`, `"repair_eligible":false`} {
		if !strings.Contains(output, field) {
			t.Errorf("missing %s in logs", field)
		}
	}
	if strings.Contains(output, "interception is translating") || strings.Contains(output, "anchor was missing") {
		t.Fatal("unknown probe claimed PF health or missing rules")
	}
}

func TestPFProbeWatchdogMeaningfulFailureRepairsWithoutMissingAnchorClaim(t *testing.T) {
	_, reloads := stubStabilizationProbe(t, []bool{false}, true)
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}})
	if got := p.checkPFWatchdogProbe(pfAnchorCheckIntact); got != pfAnchorCheckDeferred {
		t.Fatalf("probe repair must not be counted as missing-anchor restoration: %v", got)
	}
	if *reloads != 1 {
		t.Fatalf("reloads=%d", *reloads)
	}
}

func TestPFProbeWatchdogSkipsIndeterminateAnchor(t *testing.T) {
	probes, reloads := stubStabilizationProbe(t, nil, true)
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}})
	for _, r := range []pfAnchorCheckResult{pfAnchorCheckDeferred, pfAnchorCheckSkipped, pfAnchorCheckFailed, pfAnchorCheckRestored} {
		if got := p.checkPFWatchdogProbe(r); got != r {
			t.Fatalf("changed outcome %v -> %v", r, got)
		}
	}
	if *probes != 0 || *reloads != 0 {
		t.Fatal("probed without intact rule evidence")
	}
}

func TestPFProbeNoIPv4TargetIsIndeterminate(t *testing.T) {
	old := pfProbeNameservers
	t.Cleanup(func() { pfProbeNameservers = old })
	pfProbeNameservers = func() []string { return []string{"[fe80::1%en0]:53", "76.76.2.0:53"} }
	p := sourceTestProg(&prog{dnsInterceptState: &pfState{}})
	if got := p.probePFIntercept(); got.result != pfProbeIndeterminate {
		t.Fatalf("got %v", got)
	}
}

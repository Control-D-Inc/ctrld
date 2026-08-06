//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

// =============================================================================
// buildPFAnchorRules tests
// =============================================================================

func TestPFBuildAnchorRules_Basic(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	rules := p.buildPFAnchorRules(nil)

	// rdr (translation) must come before pass (filtering)
	rdrIdx := strings.Index(rules, "rdr on lo0 inet proto udp")
	passRouteIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	passInIdx := strings.Index(rules, "pass in quick on lo0 reply-to lo0")

	if rdrIdx < 0 {
		t.Fatal("missing rdr rule")
	}
	if passRouteIdx < 0 {
		t.Fatal("missing pass out route-to rule")
	}
	if passInIdx < 0 {
		t.Fatal("missing pass in on lo0 rule")
	}
	if rdrIdx >= passRouteIdx {
		t.Error("rdr rules must come before pass out route-to rules")
	}
	if passRouteIdx >= passInIdx {
		t.Error("pass out route-to must come before pass in on lo0")
	}

	// Both UDP and TCP rdr rules
	if !strings.Contains(rules, "proto udp") || !strings.Contains(rules, "proto tcp") {
		t.Error("must have both UDP and TCP rdr rules")
	}
}

func TestPFBuildAnchorRules_WithVPNServers(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
		{Server: "10.8.0.2"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// VPN exemption rules must appear
	for _, s := range vpnServers {
		if !strings.Contains(rules, s.Server) {
			t.Errorf("missing VPN exemption for %s", s.Server)
		}
	}

	// VPN exemptions must come before route-to
	exemptIdx := strings.Index(rules, "10.8.0.1 port 53 group")
	routeIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	if exemptIdx < 0 {
		t.Fatal("missing VPN exemption rule for 10.8.0.1")
	}
	if routeIdx < 0 {
		t.Fatal("missing route-to rule")
	}
	if exemptIdx >= routeIdx {
		t.Error("VPN exemptions must come before route-to rules")
	}
}

func TestPFBuildAnchorRules_IPv4AndIPv6VPN(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
		{Server: "fd00::1"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// IPv4 server should use "inet"
	lines := strings.Split(rules, "\n")
	for _, line := range lines {
		if strings.Contains(line, "10.8.0.1") && strings.HasPrefix(line, "pass") {
			if !strings.Contains(line, "inet ") {
				t.Error("IPv4 VPN server rule should contain 'inet'")
			}
			if strings.Contains(line, "inet6") {
				t.Error("IPv4 VPN server rule should not contain 'inet6'")
			}
		}
		if strings.Contains(line, "fd00::1") && strings.HasPrefix(line, "pass") {
			if !strings.Contains(line, "inet6") {
				t.Error("IPv6 VPN server rule should contain 'inet6'")
			}
		}
	}
}

func TestPFBuildAnchorRules_Ordering(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// Verify ordering: rdr → exemptions → route-to → pass in on lo0
	rdrIdx := strings.Index(rules, "rdr on lo0 inet proto udp")
	exemptIdx := strings.Index(rules, "pass out quick on ! lo0 inet proto { udp, tcp } from any to 10.8.0.1 port 53 group _ctrld")
	routeIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	passInIdx := strings.Index(rules, "pass in quick on lo0 reply-to lo0")

	if rdrIdx < 0 || exemptIdx < 0 || routeIdx < 0 || passInIdx < 0 {
		t.Fatalf("missing expected rules: rdr=%d exempt=%d route=%d passIn=%d", rdrIdx, exemptIdx, routeIdx, passInIdx)
	}

	if !(rdrIdx < exemptIdx && exemptIdx < routeIdx && routeIdx < passInIdx) {
		t.Errorf("incorrect rule ordering: rdr(%d) < exempt(%d) < route(%d) < passIn(%d)", rdrIdx, exemptIdx, routeIdx, passInIdx)
	}
}

// TestPFBuildAnchorRules_FallbackPort verifies that when the listener falls back
// to an alternate local port (e.g. 5354 because mDNSResponder owns *:53), the pf
// rdr rules redirect DNS to the ACTUAL bound port, not the configured default 53.
// Regression test for #551: pf redirected to a dead port after listener fallback.
func TestPFBuildAnchorRules_FallbackPort(t *testing.T) {
	// Configured/generated listener is 127.0.0.1:53, but the runtime bound port is 5354.
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}}}
	rules := p.buildPFAnchorRules(nil)

	// rdr must redirect to the actual bound port 5354.
	if !strings.Contains(rules, "rdr on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 5354") {
		t.Errorf("UDP rdr must redirect to bound port 5354, got:\n%s", rules)
	}
	if !strings.Contains(rules, "rdr on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 5354") {
		t.Errorf("TCP rdr must redirect to bound port 5354, got:\n%s", rules)
	}

	// The rdr redirect target must NOT point at the dead default port 53.
	// Match the exact port at line end so "port 5354" is not a false positive.
	if strings.Contains(rules, "-> 127.0.0.1 port 53\n") {
		t.Errorf("rdr must not redirect to dead port 53 after fallback, got:\n%s", rules)
	}

	// The inbound accept rule must also target the actual bound port.
	if !strings.Contains(rules, "127.0.0.1 port 5354") {
		t.Errorf("pass in rule must reference bound port 5354, got:\n%s", rules)
	}
}

// TestPFAddressFamily tests the pfAddressFamily helper.
func TestPFAddressFamily(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "inet"},
		{"192.168.1.1", "inet"},
		{"127.0.0.1", "inet"},
		{"::1", "inet6"},
		{"fd00::1", "inet6"},
		{"2001:db8::1", "inet6"},
	}
	for _, tt := range tests {
		if got := pfAddressFamily(tt.ip); got != tt.want {
			t.Errorf("pfAddressFamily(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestIsResourceExhaustion(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		output []byte
		want   bool
	}{
		{
			name: "exec start failure",
			err:  errors.New("fork/exec /sbin/pfctl: resource temporarily unavailable"),
			want: true,
		},
		{
			name:   "fd exhaustion from stderr output",
			err:    errors.New("exit status 1"),
			output: []byte("pfctl: Pipe: Too many open files"),
			want:   true,
		},
		{
			name: "process exhaustion from wrapped restore error",
			err:  errors.New("failed to dump running filter rules: exit status 1 (output: too many processes)"),
			want: true,
		},
		{
			name:   "ordinary pf syntax failure",
			err:    errors.New("exit status 1"),
			output: []byte("pfctl: syntax error"),
			want:   false,
		},
		{
			name: "nil error and empty output",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isResourceExhaustion(tt.err, tt.output); got != tt.want {
				t.Fatalf("isResourceExhaustion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func stubPFAnchorCheckCommand(t *testing.T, outputs map[string]string) {
	t.Helper()
	original := runPFAnchorCheckCommand
	runPFAnchorCheckCommand = func(args ...string) ([]byte, error) {
		key := strings.Join(args, " ")
		output, ok := outputs[key]
		if !ok {
			t.Fatalf("unexpected pf anchor check command: pfctl %s", key)
		}
		return []byte(output), nil
	}
	t.Cleanup(func() {
		runPFAnchorCheckCommand = original
	})
}

func TestEnsurePFAnchorActiveRecentRestoreWithIntactRulesDoesNotStabilize(t *testing.T) {
	stubPFAnchorCheckCommand(t, map[string]string{
		"-sn":                       `rdr-anchor "com.controld.ctrld"`,
		"-sr":                       `anchor "com.controld.ctrld"`,
		"-a com.controld.ctrld -sr": "pass in quick on lo0",
		"-a com.controld.ctrld -sn": "rdr on lo0",
	})

	p := &prog{
		dnsInterceptState: &pfState{},
		stopCh:            make(chan struct{}),
	}
	restoredAt := time.Now().Add(-time.Second).UnixMilli()
	p.pfLastRestoreTime.Store(restoredAt)

	if result := p.ensurePFAnchorActive(); result != pfAnchorCheckIntact {
		t.Fatalf("intact rules result = %v, want intact", result)
	}
	if p.pfBackoffMultiplier.Load() != 0 {
		t.Fatalf("intact rules incremented backoff to %d", p.pfBackoffMultiplier.Load())
	}
	if p.pfStabilizing.Load() {
		t.Fatal("intact rules must not enter stabilization")
	}
	if got := p.pfLastRestoreTime.Load(); got != restoredAt {
		t.Fatalf("intact check changed restore timestamp: got %d, want %d", got, restoredAt)
	}
}

func TestEnsurePFAnchorActiveCheckFailureIsNotIntact(t *testing.T) {
	original := runPFAnchorCheckCommand
	runPFAnchorCheckCommand = func(...string) ([]byte, error) {
		return nil, errors.New("pfctl unavailable")
	}
	t.Cleanup(func() { runPFAnchorCheckCommand = original })

	p := &prog{dnsInterceptState: &pfState{}}
	if result := p.ensurePFAnchorActive(); result != pfAnchorCheckFailed {
		t.Fatalf("failed PF inspection result = %v, want failed", result)
	}
}

func TestEnsurePFAnchorActiveRecentActualWipeStartsStabilization(t *testing.T) {
	stubPFAnchorCheckCommand(t, map[string]string{
		"-sn": "",
	})

	stopCh := make(chan struct{})
	close(stopCh)
	p := &prog{
		dnsInterceptState: &pfState{},
		stopCh:            stopCh,
	}
	restoredAt := time.Now().Add(-time.Second).UnixMilli()
	p.pfLastRestoreTime.Store(restoredAt)

	if result := p.ensurePFAnchorActive(); result != pfAnchorCheckDeferred {
		t.Fatalf("recent repeated wipe result = %v, want deferred", result)
	}
	if got := p.pfBackoffMultiplier.Load(); got != 1 {
		t.Fatalf("recent repeated wipe backoff = %d, want 1", got)
	}
	if got := p.pfLastRestoreTime.Load(); got != restoredAt {
		t.Fatalf("deferred restore changed restore timestamp: got %d, want %d", got, restoredAt)
	}
	deadline := time.Now().Add(time.Second)
	for p.pfStabilizing.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.pfStabilizing.Load() {
		t.Fatal("stabilization goroutine did not observe closed stop channel")
	}
}

func TestDNSInterceptIgnoredChangeReconcileDue(t *testing.T) {
	p := &prog{}
	start := time.Unix(1_000_000, 0)

	if !p.dnsInterceptIgnoredChangeReconcileDue(start) {
		t.Fatal("first ignored change must reconcile immediately")
	}
	if p.dnsInterceptIgnoredChangeReconcileDue(start.Add(pfIgnoredChangeReconcileInterval - time.Millisecond)) {
		t.Fatal("ignored changes inside the interval must be coalesced")
	}
	if !p.dnsInterceptIgnoredChangeReconcileDue(start.Add(pfIgnoredChangeReconcileInterval)) {
		t.Fatal("continuous ignored changes must reconcile again at the interval boundary")
	}
}

func TestIgnoredNetworkChangeCallbackBoundsWorkWithoutBurningStabilizedSlot(t *testing.T) {
	outputs := map[string]string{
		"-sn":                       `rdr-anchor "com.controld.ctrld"`,
		"-sr":                       `anchor "com.controld.ctrld"`,
		"-a com.controld.ctrld -sr": "pass in quick on lo0",
		"-a com.controld.ctrld -sn": "rdr on lo0",
	}
	originalCheck := runPFAnchorCheckCommand
	pfChecks := 0
	runPFAnchorCheckCommand = func(args ...string) ([]byte, error) {
		key := strings.Join(args, " ")
		output, ok := outputs[key]
		if !ok {
			t.Fatalf("unexpected pf anchor check command: pfctl %s", key)
		}
		if key == "-sn" {
			pfChecks++
		}
		return []byte(output), nil
	}
	originalDiscover := discoverTunnelInterfacesForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return nil }
	t.Cleanup(func() {
		runPFAnchorCheckCommand = originalCheck
		discoverTunnelInterfacesForReconcile = originalDiscover
	})

	refreshes := 0
	vpnDNS := newVPNDNSManager(&mainLog, nil)
	vpnDNS.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		refreshes++
		return nil
	}
	p := &prog{dnsInterceptState: &pfState{}, vpnDNS: vpnDNS}
	t.Cleanup(func() {
		p.pfDelayedRecheckMu.Lock()
		defer p.pfDelayedRecheckMu.Unlock()
		for _, timer := range p.pfDelayedRecheckTimers {
			if timer != nil {
				timer.Stop()
			}
		}
	})

	delta := &netmon.ChangeDelta{
		Old: &netmon.State{Interface: map[string]netmon.Interface{}},
		New: &netmon.State{Interface: map[string]netmon.Interface{}},
	}
	start := time.Unix(1_000_000, 0)
	p.handleDNSInterceptIgnoredNetworkChange(delta, start)
	if pfChecks != 1 || refreshes != 1 {
		t.Fatalf("first ignored delta work: pf checks=%d refreshes=%d, want 1 each", pfChecks, refreshes)
	}

	p.pfStabilizing.Store(true)
	p.handleDNSInterceptIgnoredNetworkChange(delta, start.Add(pfIgnoredChangeReconcileInterval))
	if pfChecks != 1 || refreshes != 1 {
		t.Fatalf("stabilized delta ran leading reconciliation: pf checks=%d refreshes=%d", pfChecks, refreshes)
	}

	p.pfStabilizing.Store(false)
	resumeAt := start.Add(pfIgnoredChangeReconcileInterval + time.Millisecond)
	p.handleDNSInterceptIgnoredNetworkChange(delta, resumeAt)
	if pfChecks != 2 || refreshes != 2 {
		t.Fatalf("first post-stabilization delta did not reconcile immediately: pf checks=%d refreshes=%d", pfChecks, refreshes)
	}

	for i := 1; i <= 8; i++ {
		p.handleDNSInterceptIgnoredNetworkChange(delta, resumeAt.Add(time.Duration(i)*100*time.Millisecond))
	}
	if pfChecks != 2 || refreshes != 2 {
		t.Fatalf("ignored delta burst was not coalesced: pf checks=%d refreshes=%d", pfChecks, refreshes)
	}

	p.handleDNSInterceptIgnoredNetworkChange(delta, resumeAt.Add(pfIgnoredChangeReconcileInterval))
	if pfChecks != 3 || refreshes != 3 {
		t.Fatalf("interval boundary did not reconcile: pf checks=%d refreshes=%d, want 3 each", pfChecks, refreshes)
	}
}

func TestRestorePFAnchorFailureIsNotReportedOrTimestamped(t *testing.T) {
	originalReference := ensurePFAnchorReferenceForRestore
	originalRebuild := rebuildPFAnchorRulesForReconcile
	ensurePFAnchorReferenceForRestore = func(*prog) error { return nil }
	rebuildPFAnchorRulesForReconcile = func(*prog, []vpnDNSExemption) ([]string, error) {
		return nil, errors.New("pf load failed")
	}
	t.Cleanup(func() {
		ensurePFAnchorReferenceForRestore = originalReference
		rebuildPFAnchorRulesForReconcile = originalRebuild
	})

	p := &prog{dnsInterceptState: &pfState{}}
	if result := p.restorePFAnchor("test"); result != pfAnchorCheckFailed {
		t.Fatalf("failed restore result = %v, want failed", result)
	}
	if got := p.pfLastRestoreTime.Load(); got != 0 {
		t.Fatalf("failed restore changed timestamp to %d", got)
	}
	if len(p.lastTunnelIfaces) != 0 {
		t.Fatalf("failed restore committed tunnel state: %v", p.lastTunnelIfaces)
	}
}

func TestPFStabilizationTimeoutReturnsOwnershipToDelayedRecovery(t *testing.T) {
	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	p.pfStabilizationLoopWithMaxWait(t.Context(), time.Hour, 25*time.Millisecond)

	if p.pfStabilizing.Load() {
		t.Fatal("stabilization retained ownership after the maximum wait")
	}
	p.pfDelayedRecheckMu.Lock()
	timers := append([]*time.Timer(nil), p.pfDelayedRecheckTimers...)
	p.pfDelayedRecheckTimers = nil
	p.pfDelayedRecheckMu.Unlock()
	if len(timers) != 2 {
		t.Fatalf("expected bounded timeout to schedule delayed recovery, got %d timers", len(timers))
	}
	for _, timer := range timers {
		timer.Stop()
	}
}

func TestStopDNSInterceptWaitsForInFlightPFMutation(t *testing.T) {
	binDir := t.TempDir()
	pfctlPath := filepath.Join(binDir, "pfctl")
	if err := os.WriteFile(pfctlPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	anchorFile := filepath.Join(t.TempDir(), "anchor")
	if err := os.WriteFile(anchorFile, []byte("rules"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &prog{dnsInterceptState: &pfState{anchorName: pfAnchorName, anchorFile: anchorFile}}
	p.pfEnsureRunning.Store(true)

	revoked := make(chan struct{})
	originalRevokedHook := pfShutdownStateRevokedForTest
	pfShutdownStateRevokedForTest = func() { close(revoked) }
	t.Cleanup(func() { pfShutdownStateRevokedForTest = originalRevokedHook })

	done := make(chan error, 1)
	go func() { done <- p.stopDNSIntercept() }()

	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not revoke PF lifecycle state before waiting")
	}
	select {
	case err := <-done:
		t.Fatalf("shutdown completed before in-flight PF owner released: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	p.pfEnsureRunning.Store(false)
	if err := <-done; err != nil {
		t.Fatalf("stopDNSIntercept() error: %v", err)
	}
	if _, err := os.Stat(anchorFile); !os.IsNotExist(err) {
		t.Fatalf("anchor file remained after serialized shutdown: %v", err)
	}
}

func TestPostStabilizationReconcileRetainsOwnershipAndForcesRebuild(t *testing.T) {
	stubPFAnchorCheckCommand(t, map[string]string{
		"-sn":                       `rdr-anchor "com.controld.ctrld"`,
		"-sr":                       `anchor "com.controld.ctrld"`,
		"-a com.controld.ctrld -sr": "pass in quick on lo0",
		"-a com.controld.ctrld -sn": "rdr on lo0",
	})
	originalRestore := restorePFAnchorForReconcile
	calls := 0
	restorePFAnchorForReconcile = func(*prog, string) pfAnchorCheckResult {
		calls++
		return pfAnchorCheckRestored
	}
	t.Cleanup(func() { restorePFAnchorForReconcile = originalRestore })

	p := &prog{
		dnsInterceptState:      &pfState{},
		pendingTunnelIfaces:    []string{"utun9"},
		hasPendingTunnelIfaces: true,
	}
	p.pfStabilizing.Store(true)
	if result := p.reconcilePFAnchorAfterStabilization(); result != pfAnchorCheckRestored {
		t.Fatalf("post-stabilization result = %v, want restored", result)
	}
	if calls != 1 {
		t.Fatalf("post-stabilization restore calls = %d, want 1", calls)
	}
	if !p.pfStabilizing.Load() {
		t.Fatal("post-stabilization reconcile released loop ownership")
	}
	if p.pfBackoffMultiplier.Load() != 0 {
		t.Fatalf("post-stabilization reconcile changed backoff to %d", p.pfBackoffMultiplier.Load())
	}
}

func TestPostStabilizationIntactWithoutPendingAvoidsRebuild(t *testing.T) {
	stubPFAnchorCheckCommand(t, map[string]string{
		"-sn":                       `rdr-anchor "com.controld.ctrld"`,
		"-sr":                       `anchor "com.controld.ctrld"`,
		"-a com.controld.ctrld -sr": "pass in quick on lo0",
		"-a com.controld.ctrld -sn": "rdr on lo0",
	})
	originalRestore := restorePFAnchorForReconcile
	calls := 0
	restorePFAnchorForReconcile = func(*prog, string) pfAnchorCheckResult {
		calls++
		return pfAnchorCheckRestored
	}
	t.Cleanup(func() { restorePFAnchorForReconcile = originalRestore })

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	if result := p.reconcilePFAnchorAfterStabilization(); result != pfAnchorCheckIntact {
		t.Fatalf("post-stabilization result = %v, want intact", result)
	}
	if calls != 0 {
		t.Fatalf("intact post-stabilization anchor rebuilt %d times", calls)
	}
	if !p.pfStabilizing.Load() {
		t.Fatal("intact post-stabilization reconcile released loop ownership")
	}
}

func TestTunnelRemovalFailureRetriesBeforeCommittingBaseline(t *testing.T) {
	originalDiscover := discoverTunnelInterfacesForReconcile
	originalRestore := restorePFAnchorForReconcile
	current := []string{}
	discoverTunnelInterfacesForReconcile = func() []string {
		return append([]string(nil), current...)
	}
	calls := 0
	restorePFAnchorForReconcile = func(p *prog, _ string) pfAnchorCheckResult {
		calls++
		if calls == 1 {
			return pfAnchorCheckFailed
		}
		p.commitPFReconcileState(current)
		return pfAnchorCheckRestored
	}
	t.Cleanup(func() {
		discoverTunnelInterfacesForReconcile = originalDiscover
		restorePFAnchorForReconcile = originalRestore
	})

	p := &prog{
		dnsInterceptState: &pfState{},
		lastTunnelIfaces:  []string{"utun7"},
	}
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("first tunnel removal was not detected")
	}
	if !stringSlicesEqual(p.lastTunnelIfaces, []string{"utun7"}) {
		t.Fatalf("failed removal committed baseline: %v", p.lastTunnelIfaces)
	}
	if !p.hasPendingTunnelReconcile() {
		t.Fatal("failed removal did not retain desired tunnel state for retry")
	}
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("failed tunnel removal was not retried")
	}
	if len(p.lastTunnelIfaces) != 0 {
		t.Fatalf("successful retry did not commit empty tunnel baseline: %v", p.lastTunnelIfaces)
	}
	if calls != 2 {
		t.Fatalf("restore calls = %d, want 2", calls)
	}
}

func TestPendingTunnelStateRetriesAfterStabilization(t *testing.T) {
	originalDiscover := discoverTunnelInterfacesForReconcile
	originalRestore := restorePFAnchorForReconcile
	current := []string{}
	discoverTunnelInterfacesForReconcile = func() []string { return nil }
	calls := 0
	restorePFAnchorForReconcile = func(p *prog, _ string) pfAnchorCheckResult {
		calls++
		p.commitPFReconcileState(current)
		return pfAnchorCheckRestored
	}
	t.Cleanup(func() {
		discoverTunnelInterfacesForReconcile = originalDiscover
		restorePFAnchorForReconcile = originalRestore
	})

	p := &prog{
		dnsInterceptState:      &pfState{},
		lastTunnelIfaces:       []string{"utun7"},
		pendingTunnelIfaces:    current,
		hasPendingTunnelIfaces: true,
	}
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("pending tunnel removal was not retried after stabilization")
	}
	if calls != 1 || len(p.lastTunnelIfaces) != 0 || p.hasPendingTunnelReconcile() {
		t.Fatalf("pending retry result: calls=%d baseline=%v pending=%v", calls, p.lastTunnelIfaces, p.hasPendingTunnelReconcile())
	}
}

func TestTunnelReconcileHonorsPFExecBackoff(t *testing.T) {
	originalDiscover := discoverTunnelInterfacesForReconcile
	originalRestore := restorePFAnchorForReconcile
	current := []string{}
	discoverTunnelInterfacesForReconcile = func() []string { return nil }
	calls := 0
	restorePFAnchorForReconcile = func(p *prog, _ string) pfAnchorCheckResult {
		calls++
		p.commitPFReconcileState(current)
		return pfAnchorCheckRestored
	}
	t.Cleanup(func() {
		discoverTunnelInterfacesForReconcile = originalDiscover
		restorePFAnchorForReconcile = originalRestore
	})

	p := &prog{dnsInterceptState: &pfState{}, lastTunnelIfaces: []string{"utun7"}}
	p.pfExecBackoffUntil.Store(time.Now().Add(time.Minute).UnixMilli())
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("tunnel removal was not detected during PF exec backoff")
	}
	if calls != 0 || !stringSlicesEqual(p.lastTunnelIfaces, []string{"utun7"}) {
		t.Fatalf("PF restore ran during exec backoff: calls=%d baseline=%v", calls, p.lastTunnelIfaces)
	}
	if p.checkTunnelInterfaceChanges() {
		t.Fatal("identical deferred tunnel retry bypassed the ignored-event limiter")
	}
	p.pfExecBackoffUntil.Store(0)
	if !p.checkTunnelInterfaceChanges() || calls != 1 || len(p.lastTunnelIfaces) != 0 {
		t.Fatalf("tunnel removal did not retry after backoff: calls=%d baseline=%v", calls, p.lastTunnelIfaces)
	}
}

func TestTunnelRapidReversalClearsUnappliedPendingState(t *testing.T) {
	originalDiscover := discoverTunnelInterfacesForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return nil }
	t.Cleanup(func() { discoverTunnelInterfacesForReconcile = originalDiscover })

	p := &prog{
		dnsInterceptState:      &pfState{},
		pendingTunnelIfaces:    []string{"utun9"},
		hasPendingTunnelIfaces: true,
	}
	p.pfStabilizing.Store(true)
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("rapid tunnel reversal was not observed")
	}
	if p.hasPendingTunnelReconcile() || len(p.lastTunnelIfaces) != 0 {
		t.Fatalf("rapid reversal left unapplied tunnel state: baseline=%v pending=%v", p.lastTunnelIfaces, p.hasPendingTunnelReconcile())
	}
}

func TestTunnelAdditionIsCoalescedUntilSuccessfulRebuild(t *testing.T) {
	originalDiscover := discoverTunnelInterfacesForReconcile
	current := []string{"utun9"}
	discoverTunnelInterfacesForReconcile = func() []string {
		return append([]string(nil), current...)
	}
	t.Cleanup(func() { discoverTunnelInterfacesForReconcile = originalDiscover })

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("new tunnel was not detected")
	}
	if p.checkTunnelInterfaceChanges() {
		t.Fatal("identical pending tunnel state was not coalesced")
	}
	if len(p.lastTunnelIfaces) != 0 {
		t.Fatalf("pending tunnel was committed before PF rebuild: %v", p.lastTunnelIfaces)
	}
	if !p.hasPendingTunnelReconcile() {
		t.Fatal("new tunnel was not retained as pending")
	}

	p.commitPFReconcileState(current)
	if !stringSlicesEqual(p.lastTunnelIfaces, current) {
		t.Fatalf("successful rebuild baseline = %v, want %v", p.lastTunnelIfaces, current)
	}
	if p.hasPendingTunnelReconcile() {
		t.Fatal("successful rebuild did not clear pending tunnel state")
	}
}

// TestVPNDNSRefreshDeferredWhileStabilizing covers the ignored network-change path,
// which can trigger a VPN DNS refresh from outside stabilization.
//
// A refresh rebuilds and reloads the pf anchor. Stabilization owns pf while a VPN's
// ruleset is still settling, so refreshing then is the mutual-overwrite collision
// stabilization exists to prevent - and these deltas arrive exactly when a VPN is
// coming up. Deferring is safe: checkTunnelInterfaceChanges keeps the observation
// pending, so the transition is retried afterwards.
//
// The watchdog tick carries the same guard for the same reason; it is not driven here
// because that would mean running its 30s loop.
func TestVPNDNSRefreshDeferredWhileStabilizing(t *testing.T) {
	newProg := func(t *testing.T, refreshes *int, tunnels []string) *prog {
		t.Helper()
		outputs := map[string]string{
			"-sn":                       `rdr-anchor "com.controld.ctrld"`,
			"-sr":                       `anchor "com.controld.ctrld"`,
			"-a com.controld.ctrld -sr": "pass in quick on lo0",
			"-a com.controld.ctrld -sn": "rdr on lo0",
		}
		originalCheck := runPFAnchorCheckCommand
		runPFAnchorCheckCommand = func(args ...string) ([]byte, error) {
			output, ok := outputs[strings.Join(args, " ")]
			if !ok {
				return nil, fmt.Errorf("unexpected pf anchor check command")
			}
			return []byte(output), nil
		}
		// Discovery reports no tunnels. With a seeded baseline that is a removal, which
		// checkTunnelInterfaceChanges reports as a change without touching pf while
		// stabilizing - so this fixture never reaches a real pfctl write.
		originalDiscover := discoverTunnelInterfacesForReconcile
		discoverTunnelInterfacesForReconcile = func() []string { return nil }
		t.Cleanup(func() {
			runPFAnchorCheckCommand = originalCheck
			discoverTunnelInterfacesForReconcile = originalDiscover
		})

		vpnDNS := newVPNDNSManager(&mainLog, nil)
		vpnDNS.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
			*refreshes++
			return nil
		}
		p := &prog{dnsInterceptState: &pfState{}, vpnDNS: vpnDNS, lastTunnelIfaces: tunnels}
		t.Cleanup(func() {
			p.pfDelayedRecheckMu.Lock()
			defer p.pfDelayedRecheckMu.Unlock()
			for _, timer := range p.pfDelayedRecheckTimers {
				if timer != nil {
					timer.Stop()
				}
			}
		})
		return p
	}
	delta := func() *netmon.ChangeDelta {
		return &netmon.ChangeDelta{
			Old: &netmon.State{Interface: map[string]netmon.Interface{}},
			New: &netmon.State{Interface: map[string]netmon.Interface{}},
		}
	}

	t.Run("tunnel change during stabilization does not refresh", func(t *testing.T) {
		refreshes := 0
		// Seeded baseline plus empty discovery = a tunnel transition to report, so the
		// refresh is eligible on everything except the stabilization guard.
		p := newProg(t, &refreshes, []string{"utun9"})
		p.pfStabilizing.Store(true)

		p.handleDNSInterceptIgnoredNetworkChange(delta(), time.Unix(1_000_000, 0))

		if refreshes != 0 {
			t.Errorf("refreshed %d time(s) while stabilizing — that rebuilds the anchor under a settling VPN ruleset", refreshes)
		}
	})

	t.Run("refresh still happens outside stabilization", func(t *testing.T) {
		refreshes := 0
		p := newProg(t, &refreshes, nil)

		p.handleDNSInterceptIgnoredNetworkChange(delta(), time.Unix(1_000_000, 0))

		if refreshes == 0 {
			t.Error("no refresh outside stabilization — the guard must defer, not disable")
		}
	})
}

// TestExemptVPNDNSServersDeferredWhileStabilizing checks the mutation point itself,
// not just the call sites: any future caller reaching it during stabilization is
// refused before the anchor is rewritten.
//
// It returns before pfEnsureRunning is taken and before any pfctl work, so this drives
// the real function without touching the host's pf state.
func TestExemptVPNDNSServersDeferredWhileStabilizing(t *testing.T) {
	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)

	err := p.exemptVPNDNSServers([]vpnDNSExemption{{Server: "192.168.1.1"}})
	if err == nil {
		t.Fatal("exemption applied while stabilizing — that rewrites the anchor under a settling VPN ruleset")
	}
	if !strings.Contains(err.Error(), "stabilization") {
		t.Errorf("error does not name the reason: %v", err)
	}
	// The refusal must happen before the reconcile latch is claimed, or a deferral
	// would lock out the reconcile that runs once stabilization ends.
	if p.pfEnsureRunning.Load() {
		t.Error("pfEnsureRunning was left held by a deferred exemption")
	}
}

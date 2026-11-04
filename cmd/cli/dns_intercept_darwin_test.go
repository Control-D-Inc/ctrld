//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// stubStabilizationProbe replaces the post-stabilization verification seams and returns
// counters for probe and forced-reload calls.
func stubStabilizationProbe(t *testing.T, probeResults []bool, reloadOK bool) (probes, reloads *int) {
	t.Helper()
	originalProbe, originalReload := probePFInterceptFn, forceReloadPFInterceptFn
	t.Cleanup(func() {
		probePFInterceptFn, forceReloadPFInterceptFn = originalProbe, originalReload
	})
	probeCalls, reloadCalls := 0, 0
	probePFInterceptFn = func(*prog) pfProbeObservation {
		result := false
		if probeCalls < len(probeResults) {
			result = probeResults[probeCalls]
		}
		probeCalls++
		if result {
			return pfProbeObservation{result: pfProbeIntercepted}
		}
		return pfProbeObservation{result: pfProbeNotIntercepted}
	}
	forceReloadPFInterceptFn = func(*prog) bool {
		reloadCalls++
		return reloadOK
	}
	return &probeCalls, &reloadCalls
}

// TestPostStabilizationVerifiesInterceptionFunctionally is the post-wake continuity
// boundary: the reconcile above it only proves rule text, and QA saw rules intact,
// references intact and post-load verification passed while every query through the system
// resolver timed out. Nothing else probes until the periodic watchdog, because the probe
// monitor stands down while stabilization owns pf, so recovery waited for that tick.
func TestPostStabilizationVerifiesInterceptionFunctionally(t *testing.T) {
	// Probe fails once, then passes after the reload.
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterStabilization()

	if *probes != 2 {
		t.Errorf("probe calls = %d, want 2: one to detect and one to confirm the repair", *probes)
	}
	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want exactly 1 bounded repair", *reloads)
	}
}

// TestPostStabilizationProbePassSkipsReload keeps the healthy path free of a pf reload,
// which would flush states and kill in-flight DoH connections for nothing.
func TestPostStabilizationProbePassSkipsReload(t *testing.T) {
	probes, reloads := stubStabilizationProbe(t, []bool{true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterStabilization()

	if *probes != 1 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 1/0", *probes, *reloads)
	}
}

// TestPostStabilizationRepairIsBounded pins the "one bounded recovery" contract: a probe
// that never passes must not turn into a reload loop here - the watchdog owns retries.
func TestPostStabilizationRepairIsBounded(t *testing.T) {
	probes, reloads := stubStabilizationProbe(t, []bool{false, false, false}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterStabilization()

	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want 1: the repair must not loop", *reloads)
	}
	if *probes != 2 {
		t.Errorf("probe calls = %d, want 2", *probes)
	}
}

// TestPostStabilizationWaitsForAProberThatStandsDown is the interleaving that made
// "skip when the flag is set" wrong. A probe monitor started by an ignored network change
// claims functional-probe ownership and then aborts, because stabilization still owns pf.
// If the verifier treats the claimed flag as "somebody is probing", neither path probes and
// the outage lasts until the next watchdog tick - the exact window this is meant to close.
func TestPostStabilizationWaitsForAProberThatStandsDown(t *testing.T) {
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	// Model the monitor's claim-then-abort: ownership is held, then released.
	p.pfMonitorRunning.Store(true)
	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.pfMonitorRunning.Store(false)
		close(released)
	}()

	p.verifyInterceptAfterStabilization()
	<-released

	if *probes != 2 {
		t.Errorf("probe calls = %d, want 2: the verifier must wait out a prober that stands down", *probes)
	}
	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want 1", *reloads)
	}
}

// TestPostStabilizationYieldsToAProberThatKeepsProbing is the other half of the handoff:
// when the holder is genuinely working through its probe sequence, the verifier must step
// aside rather than run a second prober against the same pf state.
func TestPostStabilizationYieldsToAProberThatKeepsProbing(t *testing.T) {
	originalWait := pfFunctionalProbeOwnerWait
	pfFunctionalProbeOwnerWait = 30 * time.Millisecond
	t.Cleanup(func() { pfFunctionalProbeOwnerWait = originalWait })

	probes, reloads := stubStabilizationProbe(t, []bool{false}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfMonitorRunning.Store(true) // held for the whole wait
	p.verifyInterceptAfterStabilization()

	if *probes != 0 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 0/0 while another prober is working", *probes, *reloads)
	}
}

// TestInterceptMonitorDoesNotClaimOwnershipWhileStabilizing pins the source of that race:
// a monitor which cannot do useful work must not take functional-probe ownership on its way
// out, or it starves the post-stabilization verifier.
func TestInterceptMonitorDoesNotClaimOwnershipWhileStabilizing(t *testing.T) {
	probes, reloads := stubStabilizationProbe(t, []bool{false}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	if p.interceptProbeMonitorAllowed() {
		t.Fatal("the probe monitor considers itself eligible while stabilization owns pf")
	}

	p.pfInterceptMonitor()

	if *probes != 0 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 0/0 from a monitor that cannot run", *probes, *reloads)
	}
	if !p.claimFunctionalProbeOwner(0) {
		t.Error("the aborted monitor left functional-probe ownership taken; the verifier would skip")
	}
	p.pfMonitorRunning.Store(false)
}

// TestFinishPFStabilizationRunsFunctionalVerification wires the fix to the production
// completion path: deleting the verification call, or reordering it before the reconcile,
// makes this fail.
func TestFinishPFStabilizationRunsFunctionalVerification(t *testing.T) {
	stubPFAnchorCheckCommand(t, map[string]string{
		"-sn":                       `rdr-anchor "com.controld.ctrld"`,
		"-sr":                       `anchor "com.controld.ctrld"`,
		"-a com.controld.ctrld -sr": "pass in quick on lo0",
		"-a com.controld.ctrld -sn": "rdr on lo0",
	})
	originalResolver := initializeOsResolver
	initializeOsResolver = func(context.Context, bool, string) []string { return nil }
	t.Cleanup(func() { initializeOsResolver = originalResolver })

	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	p.finishPFStabilization(time.Millisecond)

	if *probes == 0 {
		t.Fatal("stabilization completed without probing functional interception; recovery would wait for the watchdog")
	}
	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want 1", *reloads)
	}

	stopPFTestTimers(p)
}

// stopPFTestTimers cancels every timer a stabilization pass can leave pending.
//
// The whole test binary shares one unsynchronised log sink, so a timer that outlives its
// test logs concurrently with whichever test is running next and trips the race detector
// there - reported against the innocent test. The post-settle follow-up is a 4s timer, so
// the collision lands far from its origin.
func stopPFTestTimers(p *prog) {
	p.pfDelayedRecheckMu.Lock()
	timers := append([]*time.Timer(nil), p.pfDelayedRecheckTimers...)
	p.pfDelayedRecheckTimers = nil
	p.pfDelayedRecheckMu.Unlock()
	for _, timer := range timers {
		timer.Stop()
	}
	p.stopPFSettleFollowup()
}

// TestScheduleDNSAfterVPNSettleRefreshIsCancellable pins the tracking itself. An
// untracked follow-up cannot be cancelled by teardown or by this helper, which is how a
// 4s timer escaped its test and raced the log sink of a later one.
func TestScheduleDNSAfterVPNSettleRefreshIsCancellable(t *testing.T) {
	p := &prog{dnsInterceptState: &pfState{}}
	p.scheduleDNSAfterVPNSettleRefresh("test", time.Hour)

	p.pfDelayedRecheckMu.Lock()
	tracked := p.pfSettleFollowupTimer != nil
	p.pfDelayedRecheckMu.Unlock()
	if !tracked {
		t.Fatal("the follow-up refresh was scheduled without being tracked; nothing can cancel it")
	}

	p.stopPFSettleFollowup()
	p.pfDelayedRecheckMu.Lock()
	cleared := p.pfSettleFollowupTimer == nil
	p.pfDelayedRecheckMu.Unlock()
	if !cleared {
		t.Error("stopPFSettleFollowup left the timer in place")
	}
}

// TestScheduleDNSAfterVPNSettleRefreshReplacesPending keeps VPN churn from stacking
// repeats of the same scutil/VPN-DNS refresh.
func TestScheduleDNSAfterVPNSettleRefreshReplacesPending(t *testing.T) {
	p := &prog{dnsInterceptState: &pfState{}}
	p.scheduleDNSAfterVPNSettleRefresh("first", time.Hour)
	p.pfDelayedRecheckMu.Lock()
	first := p.pfSettleFollowupTimer
	p.pfDelayedRecheckMu.Unlock()

	p.scheduleDNSAfterVPNSettleRefresh("second", time.Hour)
	p.pfDelayedRecheckMu.Lock()
	second := p.pfSettleFollowupTimer
	p.pfDelayedRecheckMu.Unlock()
	defer p.stopPFSettleFollowup()

	if first == second {
		t.Fatal("the second schedule reused the first timer")
	}
	if first.Stop() {
		t.Error("the superseded timer was still armed; stabilization churn would stack refreshes")
	}
}

// =============================================================================
// post-wake functional verification tests
// =============================================================================

// stubWakeProbeSchedule shortens the post-resume retry schedule and neutralises the OS
// resolver refresh, so the bounded-repair contract can be tested without real delays or
// a real scutil call. It returns the number of resolver refreshes performed.
func stubWakeProbeSchedule(t *testing.T, attempts int) (refreshes *int) {
	t.Helper()
	originalDelays, originalWait := pfWakeProbeDelays, pfWakeProbeOwnerWait
	originalResolver := initializeOsResolver
	t.Cleanup(func() {
		pfWakeProbeDelays, pfWakeProbeOwnerWait = originalDelays, originalWait
		initializeOsResolver = originalResolver
	})

	pfWakeProbeDelays = make([]time.Duration, attempts)
	for i := range pfWakeProbeDelays {
		pfWakeProbeDelays[i] = time.Millisecond
	}
	pfWakeProbeOwnerWait = 10 * time.Millisecond

	calls := 0
	initializeOsResolver = func(context.Context, bool, string) []string {
		calls++
		return []string{"10.0.0.1:53"}
	}
	return &calls
}

// TestWakeProbeDetectsInterceptionBrokenBySuspend is the hole this closes. Rule text
// survives a suspend unchanged, so the watchdog reports the anchor intact, and the probe
// monitor is only armed by interface changes with a schedule frozen through the sleep.
// Nothing probed after the resume, and QA measured 18s of no public DNS on a host whose
// link and default route were already back.
func TestWakeProbeDetectsInterceptionBrokenBySuspend(t *testing.T) {
	stubWakeProbeSchedule(t, 4)
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes != 2 {
		t.Errorf("probe calls = %d, want 2: one to detect and one to confirm the repair", *probes)
	}
	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want 1", *reloads)
	}
}

// TestWakeProbePassStopsImmediately keeps a healthy resume free of pf work: a reload
// flushes pf state and kills in-flight DoH connections for nothing.
func TestWakeProbePassStopsImmediately(t *testing.T) {
	stubWakeProbeSchedule(t, 4)
	probes, reloads := stubStabilizationProbe(t, []bool{true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes != 1 {
		t.Errorf("probe calls = %d, want 1: a passing probe must end the schedule", *probes)
	}
	if *reloads != 0 {
		t.Errorf("forced reloads = %d, want 0 on a healthy resume", *reloads)
	}
}

// TestWakeProbeRetriesAcrossTheSchedule covers the observed shape directly: the first
// forced reload did not restore translation and a later one did, so a single attempt is
// not enough. The second repair must still happen, and the confirming pass must end it.
func TestWakeProbeRetriesAcrossTheSchedule(t *testing.T) {
	stubWakeProbeSchedule(t, 4)
	// attempt 1: probe fails, reload, confirm fails.
	// attempt 2: probe fails, reload, confirm passes.
	probes, reloads := stubStabilizationProbe(t, []bool{false, false, false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *reloads != 2 {
		t.Errorf("forced reloads = %d, want 2: one failed repair must not end the schedule", *reloads)
	}
	if *probes != 4 {
		t.Errorf("probe calls = %d, want 4", *probes)
	}
}

// TestWakeProbeRepairsAreBounded pins the bound. A probe that never passes must exhaust
// the repair budget and then keep probing without reloading, so this can never become the
// unbounded reload loop the issue rules out.
func TestWakeProbeRepairsAreBounded(t *testing.T) {
	stubWakeProbeSchedule(t, 6)
	probes, reloads := stubStabilizationProbe(t, nil, true) // every probe fails

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *reloads != pfWakeMaxRepairs {
		t.Errorf("forced reloads = %d, want the budget of %d", *reloads, pfWakeMaxRepairs)
	}
	// Two repaired attempts probe twice each; the remaining four probe once each.
	if want := 2*pfWakeMaxRepairs + (6 - pfWakeMaxRepairs); *probes != want {
		t.Errorf("probe calls = %d, want %d", *probes, want)
	}
	if p.pfMonitorRunning.Load() {
		t.Error("functional-probe ownership was left held after the schedule finished")
	}
}

// TestWakeProbeRefreshesResolverBeforeEveryProbe is why a stale list matters: the probe
// aims at the first OS nameserver and reports success when it has none, so a list still
// holding a pre-sleep VPN resolver turns the probe into a meaningless pass or a false
// failure. The captured run showed the resolver set changing after the resume.
func TestWakeProbeRefreshesResolverBeforeEveryProbe(t *testing.T) {
	refreshes := stubWakeProbeSchedule(t, 3)
	stubStabilizationProbe(t, nil, false) // probes fail, reload refuses to run

	p := &prog{dnsInterceptState: &pfState{}}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *refreshes != 3 {
		t.Errorf("OS resolver refreshes = %d, want one per attempt (3)", *refreshes)
	}
}

// TestWakeProbeStandsDownForStabilization keeps the two repair paths from fighting over
// pf. Stabilization owns the ruleset while a VPN settles and runs its own functional
// verification when it finishes; reloading underneath it is the mutual overwriting
// stabilization exists to prevent.
func TestWakeProbeStandsDownForStabilization(t *testing.T) {
	stubWakeProbeSchedule(t, 4)
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfStabilizing.Store(true)
	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes != 0 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 0/0 while stabilization owns pf", *probes, *reloads)
	}
	if !p.claimFunctionalProbeOwner(0) {
		t.Error("standing down took functional-probe ownership; the post-stabilization verifier would skip")
	}
	p.pfMonitorRunning.Store(false)
}

// TestWakeProbeYieldsToAnotherProberThenRetries is the ownership handoff. A probe monitor
// that is genuinely working owns this attempt, but the schedule must not be spent waiting
// on it: the next attempt still has to probe once ownership is free.
func TestWakeProbeYieldsToAnotherProberThenRetries(t *testing.T) {
	stubWakeProbeSchedule(t, 3)
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfMonitorRunning.Store(true)
	go func() {
		time.Sleep(30 * time.Millisecond)
		p.pfMonitorRunning.Store(false)
	}()

	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes == 0 {
		t.Fatal("the schedule gave up entirely because another prober held ownership at first")
	}
	if *reloads != 1 {
		t.Errorf("forced reloads = %d, want 1", *reloads)
	}
}

// TestWakeProbeSkippedDuringExecBackoff protects the resource-exhaustion guard: each
// probe forks a helper, which is exactly what backoff exists to stop.
func TestWakeProbeSkippedDuringExecBackoff(t *testing.T) {
	stubWakeProbeSchedule(t, 3)
	probes, reloads := stubStabilizationProbe(t, []bool{false, true}, true)

	p := &prog{dnsInterceptState: &pfState{}}
	p.pfExecBackoffUntil.Store(time.Now().Add(time.Minute).UnixMilli())
	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes != 0 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 0/0 during pf exec backoff", *probes, *reloads)
	}
}

// TestWakeProbeSkippedWhenInterceptDisabled keeps the watcher harmless when intercept
// mode is off: the detector runs for the process, the repair is intercept-only.
func TestWakeProbeSkippedWhenInterceptDisabled(t *testing.T) {
	stubWakeProbeSchedule(t, 3)
	probes, reloads := stubStabilizationProbe(t, []bool{false}, true)

	p := &prog{}
	p.verifyInterceptAfterWake(18 * time.Second)

	if *probes != 0 || *reloads != 0 {
		t.Errorf("probe calls = %d, forced reloads = %d, want 0/0 with intercept disabled", *probes, *reloads)
	}
}

// TestWakeProbeStopsWhenServiceStops keeps a resume during shutdown from holding the
// schedule open past the stop request.
func TestWakeProbeStopsWhenServiceStops(t *testing.T) {
	originalDelays := pfWakeProbeDelays
	pfWakeProbeDelays = []time.Duration{0, time.Hour}
	t.Cleanup(func() { pfWakeProbeDelays = originalDelays })
	originalResolver := initializeOsResolver
	initializeOsResolver = func(context.Context, bool, string) []string { return []string{"10.0.0.1:53"} }
	t.Cleanup(func() { initializeOsResolver = originalResolver })

	probes, _ := stubStabilizationProbe(t, nil, false) // first probe fails, reload refuses

	stopCh := make(chan struct{})
	close(stopCh)
	p := &prog{dnsInterceptState: &pfState{}, stopCh: stopCh}

	done := make(chan struct{})
	go func() {
		p.verifyInterceptAfterWake(18 * time.Second)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("verifyInterceptAfterWake ignored the stop request and waited out its schedule")
	}
	if *probes != 1 {
		t.Errorf("probe calls = %d, want 1 before the stop was observed", *probes)
	}
}

// =============================================================================
// post-wake watcher registration tests
// =============================================================================

// TestStartInterceptBackgroundWorkRegistersTheWakeVerifier covers the caller wiring. The
// detector and the wake-repair path can both be correct while nothing connects them, and
// then a host sleep is never noticed in production.
func TestStartInterceptBackgroundWorkRegistersTheWakeVerifier(t *testing.T) {
	type registration struct {
		stopCh   <-chan struct{}
		onResume func(time.Duration)
	}
	registered := make(chan registration, 1)
	watchdogStarted := make(chan struct{}, 1)
	originalWatcher, originalWatchdog := runSuspendWatcherFn, pfWatchdogFn
	runSuspendWatcherFn = func(stopCh <-chan struct{}, onResume func(time.Duration)) {
		registered <- registration{stopCh: stopCh, onResume: onResume}
	}
	// Both loops are stubbed rather than run: each would reach pfctl, and stopping the
	// real watchdog means closing stopCh, which the wake verifier reads as "service
	// stopping" and would abandon its probe schedule before the first probe.
	pfWatchdogFn = func(*prog) { watchdogStarted <- struct{}{} }
	t.Cleanup(func() { runSuspendWatcherFn, pfWatchdogFn = originalWatcher, originalWatchdog })

	stubWakeProbeSchedule(t, 4)
	probes, _ := stubStabilizationProbe(t, []bool{false, true}, true)

	// Open for the whole test: an active intercept is not stopping.
	stopCh := make(chan struct{})
	p := &prog{dnsInterceptState: &pfState{}, stopCh: stopCh}
	p.startInterceptBackgroundWork()

	select {
	case <-watchdogStarted:
	case <-time.After(2 * time.Second):
		t.Error("no pf watchdog was started; a replaced pf ruleset would never be restored")
	}

	var reg registration
	select {
	case reg = <-registered:
	case <-time.After(2 * time.Second):
		t.Fatal("no suspend watcher was started; a host sleep would go unnoticed")
	}
	if reg.stopCh != stopCh {
		t.Error("the watcher was not wired to the service stop channel; it would outlive the intercept")
	}

	// Prove the callback is the post-wake verifier and not some other function: a
	// reported resume has to probe interception. How many probes and repairs that
	// schedule is worth belongs to TestWakeProbeDetectsInterceptionBrokenBySuspend;
	// pinning it again here would only couple this test to that tuning.
	reg.onResume(18 * time.Second)
	if *probes == 0 {
		t.Error("the resume callback probed nothing; it is not wired to verifyInterceptAfterWake")
	}
}

// TestStartDNSInterceptStartsBackgroundWork closes the caller-wiring gap. Everything the
// privileged install does sits behind installPFInterceptFn, so this drives the real
// startDNSIntercept and checks what a successful start hands off: without the handoff, an
// active intercept runs with no pf watchdog and no post-wake verification, and every
// detector, recovery and registration test still passes.
func TestStartDNSInterceptStartsBackgroundWork(t *testing.T) {
	installed := 0
	originalInstall := installPFInterceptFn
	installPFInterceptFn = func(*prog) error { installed++; return nil }
	originalDiscover := discoverTunnelInterfacesForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return nil }

	watchdogStarted := make(chan struct{}, 1)
	watcherStarted := make(chan struct{}, 1)
	originalWatchdog, originalWatcher := pfWatchdogFn, runSuspendWatcherFn
	pfWatchdogFn = func(*prog) { watchdogStarted <- struct{}{} }
	runSuspendWatcherFn = func(<-chan struct{}, func(time.Duration)) { watcherStarted <- struct{}{} }
	t.Cleanup(func() {
		installPFInterceptFn = originalInstall
		discoverTunnelInterfacesForReconcile = originalDiscover
		pfWatchdogFn, runSuspendWatcherFn = originalWatchdog, originalWatcher
	})

	p := &prog{
		cfg:    &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}},
		stopCh: make(chan struct{}),
	}
	if err := p.startDNSIntercept(); err != nil {
		t.Fatalf("startDNSIntercept() = %v, want nil", err)
	}
	if installed != 1 {
		t.Errorf("privileged install ran %d times, want 1", installed)
	}
	if p.dnsInterceptState == nil {
		t.Fatal("a successful start did not publish intercept state")
	}

	select {
	case <-watchdogStarted:
	case <-time.After(2 * time.Second):
		t.Error("startDNSIntercept did not start the pf watchdog; a replaced pf ruleset would never be restored")
	}
	select {
	case <-watcherStarted:
	case <-time.After(2 * time.Second):
		t.Error("startDNSIntercept did not start the suspend watcher; a host sleep would go unnoticed")
	}
}

// TestStartDNSInterceptSkipsBackgroundWorkWhenInstallFails keeps the handoff conditional:
// watchers over an intercept that was never installed would repair state nothing owns.
func TestStartDNSInterceptSkipsBackgroundWorkWhenInstallFails(t *testing.T) {
	originalInstall := installPFInterceptFn
	installPFInterceptFn = func(*prog) error { return errors.New("pf unavailable") }
	originalWatchdog, originalWatcher := pfWatchdogFn, runSuspendWatcherFn
	pfWatchdogFn = func(*prog) { t.Error("the pf watchdog started after a failed install") }
	runSuspendWatcherFn = func(<-chan struct{}, func(time.Duration)) {
		t.Error("the suspend watcher started after a failed install")
	}
	t.Cleanup(func() {
		installPFInterceptFn = originalInstall
		pfWatchdogFn, runSuspendWatcherFn = originalWatchdog, originalWatcher
	})

	p := &prog{stopCh: make(chan struct{})}
	if err := p.startDNSIntercept(); err == nil {
		t.Fatal("startDNSIntercept() = nil after the privileged install failed")
	}
	if p.dnsInterceptState != nil {
		t.Error("a failed start published intercept state; the caller would skip its DNS fallback")
	}
	// The goroutines above are started before this returns if at all, but give a failing
	// wiring a moment to report rather than racing the test's end.
	time.Sleep(50 * time.Millisecond)
}

// =============================================================================
// pf anchor state, tunnel, and wake event tests
// =============================================================================

// pfStateCommandsMu guards the answer of the pf and tunnel state reads, because
// a watchdog or stabilization goroutine can read while a test replaces it.
var (
	pfStateCommandsMu sync.Mutex
	pfStateCommandFn  func(string, ...string) ([]byte, error)
)

// init keeps the whole test binary away from pfctl and ifconfig. A test that
// needs values stubs them with stubPFStateCommands.
func init() {
	pfStateRunCommand = func(name string, args ...string) ([]byte, error) {
		pfStateCommandsMu.Lock()
		run := pfStateCommandFn
		pfStateCommandsMu.Unlock()
		if run == nil {
			return nil, errors.New("pf state read is not stubbed")
		}
		return run(name, args...)
	}
}

// stubPFStateCommands answers the pf and tunnel state reads from fixture text,
// keyed by the whole command line.
func stubPFStateCommands(t *testing.T, outputs map[string]string) {
	t.Helper()
	stubPFStateCommandFn(t, func(name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		output, ok := outputs[key]
		if !ok {
			return nil, fmt.Errorf("no fixture for %q", key)
		}
		return []byte(output), nil
	})
}

// stubPFStateCommandFn answers the pf and tunnel state reads from run.
func stubPFStateCommandFn(t *testing.T, run func(string, ...string) ([]byte, error)) {
	t.Helper()
	pfStateCommandsMu.Lock()
	original := pfStateCommandFn
	pfStateCommandFn = run
	pfStateCommandsMu.Unlock()
	t.Cleanup(func() {
		pfStateCommandsMu.Lock()
		pfStateCommandFn = original
		pfStateCommandsMu.Unlock()
	})
}

// pfIntactAnchorRules answers the anchor check of a healthy ruleset.
var pfIntactAnchorRules = map[string]string{
	"-sn":                       `rdr-anchor "com.controld.ctrld"`,
	"-sr":                       `anchor "com.controld.ctrld"`,
	"-a com.controld.ctrld -sr": "pass in quick on lo0",
	"-a com.controld.ctrld -sn": "rdr on lo0",
}

// pfStateFixtures answers the anchor list and status reads with a real ruleset.
var pfStateFixtures = map[string]string{
	"pfctl -sr": pfShowRules,
	"pfctl -sn": pfShowNAT,
	"pfctl -si": pfStatusEnabled,
}

// waitForStabilizationExit waits for the stabilization loop to release pf.
func waitForStabilizationExit(t *testing.T, p *prog) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.pfStabilizing.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.pfStabilizing.Load() {
		t.Fatal("the stabilization loop did not observe the closed stop channel")
	}
}

// Test_logPFAnchorListLogsStabilizationStartAndEnd covers the anchor list at the
// two stabilization events. A capture of a VPN connect has to name the anchors
// that were loaded before ctrld waited, and the ones that were loaded after.
func Test_logPFAnchorListLogsStabilizationStartAndEnd(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)
	stubPFAnchorCheckCommand(t, pfIntactAnchorRules)
	originalResolver := initializeOsResolver
	initializeOsResolver = func(context.Context, bool, string) []string { return nil }
	t.Cleanup(func() { initializeOsResolver = originalResolver })
	stubStabilizationProbe(t, []bool{true}, true)

	stopCh := make(chan struct{})
	close(stopCh)
	p := &prog{dnsInterceptState: &pfState{}, stopCh: stopCh}
	p.pfStartStabilization()
	waitForStabilizationExit(t, p)
	p.pfStabilizing.Store(true)
	p.finishPFStabilization(time.Millisecond)
	stopPFTestTimers(p)

	events := jsonLogEvents(t, logs, "PF anchor list changed")
	if len(events) != 2 {
		t.Fatalf("got %d anchor list events for one stabilization, want 2", len(events))
	}
	wantField(t, events[0], "reason", "stabilization_start")
	wantField(t, events[0], "journal", true)
	wantField(t, events[0], "pf_enabled", true)
	wantField(t, events[0], "pf_since", "0 days 02:11:05")
	wantAnchors(t, events[0], []string{"com.apple/*", "com.controld.ctrld"})
	wantField(t, events[1], "reason", "stabilization_end")
	wantField(t, events[1], "journal", true)

	for _, prefix := range []string{
		"DNS intercept: VPN connecting",
		"DNS intercept: pf stable for",
	} {
		lines := eventsWithPrefix(t, logs, prefix)
		if len(lines) != 1 {
			t.Fatalf("got %d lines with prefix %q, want 1", len(lines), prefix)
		}
		wantField(t, lines[0], "journal", true)
	}
}

// Test_logPFAnchorListReportsAMissingAnchorOnce covers the watchdog state. The
// anchor stays missing for as long as another program holds pf, and one line per
// tick would fill the journal with the same fact.
func Test_logPFAnchorListReportsAMissingAnchorOnce(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)
	outputs := pfIntactAnchorRules
	original := runPFAnchorCheckCommand
	runPFAnchorCheckCommand = func(args ...string) ([]byte, error) {
		return []byte(outputs[strings.Join(args, " ")]), nil
	}
	originalRestore := restorePFAnchorForReconcile
	restorePFAnchorForReconcile = func(*prog, string) pfAnchorCheckResult { return pfAnchorCheckRestored }
	t.Cleanup(func() {
		runPFAnchorCheckCommand = original
		restorePFAnchorForReconcile = originalRestore
	})

	p := &prog{dnsInterceptState: &pfState{}}
	for range 3 {
		if result := p.ensurePFAnchorActive(); result != pfAnchorCheckIntact {
			t.Fatalf("healthy check result = %v, want intact", result)
		}
	}
	intact := eventsWithPrefix(t, logs, "DNS intercept watchdog: pf anchor intact")
	if len(intact) != 1 {
		t.Fatalf("got %d intact lines for three healthy checks, want 1", len(intact))
	}
	wantField(t, intact[0], "repeats", float64(0))

	outputs = map[string]string{}
	for range 2 {
		if result := p.ensurePFAnchorActive(); result != pfAnchorCheckRestored {
			t.Fatalf("wiped check result = %v, want restored", result)
		}
	}
	missing := jsonLogEvents(t, logs, "PF anchor list changed")
	if len(missing) != 1 {
		t.Fatalf("got %d anchor list events for two wiped checks, want 1", len(missing))
	}
	wantField(t, missing[0], "reason", "missing")
	wantField(t, missing[0], "level", "warn")
	wantField(t, missing[0], "journal", true)

	outputs = pfIntactAnchorRules
	if result := p.ensurePFAnchorActive(); result != pfAnchorCheckIntact {
		t.Fatalf("recovered check result = %v, want intact", result)
	}
	intact = eventsWithPrefix(t, logs, "DNS intercept watchdog: pf anchor intact")
	if len(intact) != 2 {
		t.Fatalf("got %d intact lines after the anchor came back, want 2", len(intact))
	}
	// The second wiped check repeated the state of the first one, and that held
	// line is the count the recovered line carries.
	wantField(t, intact[1], "repeats", float64(1))
}

// Test_logPFAnchorListReportsARestoredAnchor covers the restore report. The
// missing event alone leaves a capture without the anchors ctrld ended with.
func Test_logPFAnchorListReportsARestoredAnchor(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)
	originalReference := ensurePFAnchorReferenceForRestore
	originalRebuild := rebuildPFAnchorRulesForReconcile
	originalVerify := verifyPFStateFn
	ensurePFAnchorReferenceForRestore = func(*prog) error { return nil }
	rebuildPFAnchorRulesForReconcile = func(*prog, []vpnDNSExemption) ([]string, error) { return nil, nil }
	verifyPFStateFn = func(*prog) bool { return true }
	t.Cleanup(func() {
		ensurePFAnchorReferenceForRestore = originalReference
		rebuildPFAnchorRulesForReconcile = originalRebuild
		verifyPFStateFn = originalVerify
	})

	p := &prog{dnsInterceptState: &pfState{}}
	if result := p.restorePFAnchorWithTransportReset("test", false); result != pfAnchorCheckRestored {
		t.Fatalf("restore result = %v, want restored", result)
	}

	events := jsonLogEvents(t, logs, "PF anchor list changed")
	if len(events) != 1 {
		t.Fatalf("got %d anchor list events for one restore, want 1", len(events))
	}
	wantField(t, events[0], "reason", "restored")
	wantField(t, events[0], "level", "info")
	wantField(t, events[0], "journal", true)
	wantAnchors(t, events[0], []string{"com.apple/*", "com.controld.ctrld"})
}

// Test_logPFAnchorListMarksAnUnknownAnchorList covers a failed read. pfctl fails
// on a host that revoked the privileges of ctrld, and an empty list there reads
// as a ruleset that holds no anchor at all.
func Test_logPFAnchorListMarksAnUnknownAnchorList(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, nil)

	p := &prog{}
	p.logPFAnchorList(pfAnchorReasonRestored, mainLog.Load().Info(), pfRuleDump{})

	events := jsonLogEvents(t, logs, "PF anchor list changed")
	if len(events) != 1 {
		t.Fatalf("got %d anchor list events, want 1", len(events))
	}
	wantField(t, events[0], "anchors_known", false)
	if _, ok := events[0]["anchors"]; ok {
		t.Fatalf("a failed read reported an anchor list: %v", events[0])
	}
}

// TestTunnelInterfaceChangedNamesTheOwner covers the tunnel event. The #611
// capture could not tell a VPN tunnel from a mesh client, and the owner is the
// field that names the program whose pf rules compete with the ctrld anchor.
func TestTunnelInterfaceChangedNamesTheOwner(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, map[string]string{"ifconfig -v utun9": ifconfigWindscribeTunnel})
	originalDiscover := discoverTunnelInterfacesForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return []string{"utun9"} }
	t.Cleanup(func() { discoverTunnelInterfacesForReconcile = originalDiscover })

	p := &prog{dnsInterceptState: &pfState{}, lastTunnelIfaces: []string{"utun7"}}
	// Stabilization owns the rebuild, so the event is all this drives.
	p.pfStabilizing.Store(true)
	if !p.checkTunnelInterfaceChanges() {
		t.Fatal("the tunnel set change was not observed")
	}

	events := jsonLogEvents(t, logs, "Tunnel interface changed")
	if len(events) != 1 {
		t.Fatalf("got %d tunnel events for one set change, want 1", len(events))
	}
	wantField(t, events[0], "owner", "Windscribe VPN")
	wantField(t, events[0], "journal", true)
	wantStrings(t, events[0], "added", []string{"utun9"})
	wantStrings(t, events[0], "removed", []string{"utun7"})

	discovered := eventsWithPrefix(t, logs, "DNS intercept: discovered active tunnel interfaces")
	if len(discovered) != 1 {
		t.Fatalf("got %d discovery lines for one tunnel set, want 1", len(discovered))
	}
	if p.checkTunnelInterfaceChanges() {
		t.Fatal("the identical pending tunnel set was not coalesced")
	}
	discovered = eventsWithPrefix(t, logs, "DNS intercept: discovered active tunnel interfaces")
	if len(discovered) != 1 {
		t.Fatalf("got %d discovery lines for an unchanged tunnel set, want 1", len(discovered))
	}
}

// TestVerifyInterceptAfterWakeReportsTheWake covers the detector source of the
// wake event. The 2026-09-14 capture has no wake line at all, and the resolver
// table after a resume is the state the investigation needs next.
func TestVerifyInterceptAfterWakeReportsTheWake(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubWakeProbeSchedule(t, 4)
	stubStabilizationProbe(t, []bool{true}, true)
	now := time.Date(2026, 9, 14, 7, 14, 0, 0, time.UTC)
	originalNow := networkEventsNowFn
	networkEventsNowFn = func() time.Time { return now }
	t.Cleanup(func() { networkEventsNowFn = originalNow })

	p := &prog{
		dnsInterceptState: &pfState{},
		dnsConfig:         newDNSConfigPoller(func() ([]dnsResolverEntry, error) { return nil, nil }),
	}
	p.verifyInterceptAfterWake(18 * time.Second)

	events := jsonLogEvents(t, logs, hostWokeMessage)
	if len(events) != 1 {
		t.Fatalf("got %d Host woke events for one resume, want 1", len(events))
	}
	wantField(t, events[0], "source", "detector")
	wantField(t, events[0], "gap_ms", float64(18000))
	wantField(t, events[0], "journal", true)
	if got := p.dnsConfig.nextDelay(now); got != dnsConfigFastInterval {
		t.Fatalf("DNS configuration poll delay after a wake = %s, want %s", got, dnsConfigFastInterval)
	}
}

func wantAnchors(t *testing.T, event map[string]any, want []string) {
	t.Helper()
	wantStrings(t, event, "anchors", want)
}

func wantStrings(t *testing.T, event map[string]any, field string, want []string) {
	t.Helper()
	values, ok := event[field].([]any)
	if !ok {
		t.Fatalf("field %q: got %v, want a list", field, event[field])
	}
	if len(values) != len(want) {
		t.Fatalf("field %q: got %v, want %v", field, values, want)
	}
	for i, value := range values {
		if value != want[i] {
			t.Fatalf("field %q: got %v, want %v", field, values, want)
		}
	}
}

// TestIgnoredNetworkChangeJournalsTheInterfaceChange proves that an interface
// that appears or disappears on the ignored path enters the journal with its
// class and its action, so a hypervisor adapter storm is readable after the fact.
func TestIgnoredNetworkChangeJournalsTheInterfaceChange(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	stubSnapshotVirtualSet(t, "bridge101")
	originalDiscover := discoverTunnelInterfacesForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return nil }
	t.Cleanup(func() { discoverTunnelInterfacesForReconcile = originalDiscover })

	p := &prog{dnsInterceptState: &pfState{}, vpnDNS: newVPNDNSManager(&mainLog, nil)}
	p.pfStabilizing.Store(true)
	t.Cleanup(func() {
		p.pfDelayedRecheckMu.Lock()
		defer p.pfDelayedRecheckMu.Unlock()
		for _, timer := range p.pfDelayedRecheckTimers {
			if timer != nil {
				timer.Stop()
			}
		}
	})
	stateWith := func(names ...string) *netmon.State {
		state := &netmon.State{Interface: map[string]netmon.Interface{}}
		for _, name := range names {
			state.Interface[name] = netmon.Interface{Interface: &net.Interface{Name: name, Flags: net.FlagUp}}
		}
		return state
	}
	now := time.Unix(1_000_000, 0)

	p.handleDNSInterceptIgnoredNetworkChange(&netmon.ChangeDelta{Old: stateWith("en0"), New: stateWith("en0", "bridge101")}, now)
	p.handleDNSInterceptIgnoredNetworkChange(&netmon.ChangeDelta{Old: stateWith("en0", "bridge101"), New: stateWith("en0")}, now.Add(time.Second))

	events := jsonLogEvents(t, logs, "DNS intercept: interface appeared/disappeared — starting interception probe monitor")
	if len(events) != 2 {
		t.Fatalf("interface events: got %d, want 2: %s", len(events), logs.String())
	}
	for i, action := range []string{"added", "removed"} {
		wantField(t, events[i], "journal", true)
		wantField(t, events[i], "interface", "bridge101")
		wantField(t, events[i], "class", "virtual")
		wantField(t, events[i], "action", action)
	}
}

// TestTunnelInterfaceChangedLogsOncePerChange covers the retry path and the
// flap back. The reconcile keeps a new tunnel set pending until it succeeds,
// so every retry repeated the same event, and a set that returned to the one
// before it reported nothing at all.
func TestTunnelInterfaceChangedLogsOncePerChange(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)
	originalDiscover := discoverTunnelInterfacesForReconcile
	originalRestore := restorePFAnchorForReconcile
	discoverTunnelInterfacesForReconcile = func() []string { return []string{"utun7"} }
	restorePFAnchorForReconcile = func(*prog, string) pfAnchorCheckResult { return pfAnchorCheckFailed }
	t.Cleanup(func() {
		discoverTunnelInterfacesForReconcile = originalDiscover
		restorePFAnchorForReconcile = originalRestore
	})

	p := &prog{dnsInterceptState: &pfState{}, lastTunnelIfaces: []string{"utun7", "utun9"}}
	for range 3 {
		p.checkTunnelInterfaceChanges()
	}

	events := jsonLogEvents(t, logs, tunnelChangedMessage)
	if len(events) != 1 {
		t.Fatalf("got %d tunnel events for three retries of one change, want 1", len(events))
	}
	wantStrings(t, events[0], "removed", []string{"utun9"})

	// The tunnel comes back before a reconcile applied its removal.
	discoverTunnelInterfacesForReconcile = func() []string { return []string{"utun7", "utun9"} }
	p.checkTunnelInterfaceChanges()

	events = jsonLogEvents(t, logs, tunnelChangedMessage)
	if len(events) != 2 {
		t.Fatalf("got %d tunnel events after the tunnel came back, want 2", len(events))
	}
	wantStrings(t, events[1], "added", []string{"utun9"})
}

// TestPFAnchorWipeAfterRestoreReportsTheMissingAnchor covers the wipe that
// follows a restore within ten seconds. That path enters stabilization instead
// of a rebuild, and it left the journal without the wipe that caused it.
func TestPFAnchorWipeAfterRestoreReportsTheMissingAnchor(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)
	stubPFAnchorCheckCommand(t, map[string]string{"-sn": ""})
	stubStabilizationProbe(t, []bool{true}, true)
	stopCh := make(chan struct{})
	close(stopCh)

	p := &prog{dnsInterceptState: &pfState{}, stopCh: stopCh}
	p.pfLastRestoreTime.Store(time.Now().UnixMilli())

	if result := p.ensurePFAnchorActive(); result != pfAnchorCheckDeferred {
		t.Fatalf("wipe after restore result = %v, want deferred", result)
	}
	waitForStabilizationExit(t, p)
	stopPFTestTimers(p)

	events := jsonLogEvents(t, logs, pfAnchorListMessage)
	if len(events) != 2 {
		t.Fatalf("got %d anchor list events for one wipe, want 2", len(events))
	}
	wantField(t, events[0], "reason", pfAnchorReasonMissing)
	wantField(t, events[0], "level", "warn")
	wantField(t, events[1], "reason", pfAnchorReasonStabilizationStart)
}

// TestPFAnchorListParsesTheRulesTheCallerHolds covers the anchor read of the
// watchdog. The watchdog already read both rule sets, and one more pair of
// pfctl processes on the network change path is work the host does not need.
func TestPFAnchorListParsesTheRulesTheCallerHolds(t *testing.T) {
	logs := captureDebugMainLog(t)
	var reads []string
	stubPFStateCommandFn(t, func(name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		reads = append(reads, key)
		output, ok := pfStateFixtures[key]
		if !ok {
			return nil, fmt.Errorf("no fixture for %q", key)
		}
		return []byte(output), nil
	})

	p := &prog{}
	p.logPFAnchorList(pfAnchorReasonMissing, mainLog.Load().Warn(), pfRuleDump{
		rules: []byte(pfShowRules),
		nat:   []byte(pfShowNAT),
	})

	if want := []string{"pfctl -si"}; !slices.Equal(reads, want) {
		t.Fatalf("pf state reads = %v, want %v", reads, want)
	}
	events := jsonLogEvents(t, logs, pfAnchorListMessage)
	if len(events) != 1 {
		t.Fatalf("got %d anchor list events, want 1", len(events))
	}
	wantAnchors(t, events[0], []string{"com.apple/*", "com.controld.ctrld"})
	wantField(t, events[0], "pf_enabled", true)
}

// TestPFAnchorListBacksOffOnExhaustedResources covers a failed anchor read.
// Every other pfctl read feeds the backoff, so the anchor read kept starting
// processes on a host that had none left.
func TestPFAnchorListBacksOffOnExhaustedResources(t *testing.T) {
	captureDebugMainLog(t)
	stubPFStateCommandFn(t, func(string, ...string) ([]byte, error) {
		return nil, errors.New("fork/exec /sbin/pfctl: resource temporarily unavailable")
	})

	p := &prog{}
	p.logPFAnchorList(pfAnchorReasonRestored, mainLog.Load().Info(), pfRuleDump{})

	if !p.pfExecBackoffActive() {
		t.Fatal("a failed anchor read did not start the pfctl backoff")
	}
}

// TestPFAnchorListMarksATruncatedRuleListUnknown covers an oversized read. A
// reader stops at a line it cannot hold, and the anchors it collected before
// that line read as a ruleset that lost the rest of them.
func TestPFAnchorListMarksATruncatedRuleListUnknown(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubPFStateCommands(t, pfStateFixtures)

	p := &prog{}
	p.logPFAnchorList(pfAnchorReasonRestored, mainLog.Load().Info(), pfRuleDump{
		rules: []byte(pfShowRules + strings.Repeat("a", 70<<10) + "\n"),
		nat:   []byte(pfShowNAT),
	})

	events := jsonLogEvents(t, logs, pfAnchorListMessage)
	if len(events) != 1 {
		t.Fatalf("got %d anchor list events, want 1", len(events))
	}
	wantField(t, events[0], "anchors_known", false)
	if _, ok := events[0]["anchors"]; ok {
		t.Fatalf("a truncated read reported an anchor list: %v", events[0])
	}
}

// TestPFStateOutputIsBounded covers the memory a state read can take. A pfctl
// that prints without end must not grow the daemon.
func TestPFStateOutputIsBounded(t *testing.T) {
	out := &boundedBuffer{limit: 8}
	if _, err := out.Write([]byte("12345")); err != nil {
		t.Fatalf("write below the limit: %v", err)
	}
	if _, err := out.Write([]byte("67890")); err != nil {
		t.Fatalf("write above the limit: %v", err)
	}
	if !out.exceeded {
		t.Fatal("the writer did not report the dropped bytes")
	}
	if got := out.Len(); got > 8 {
		t.Fatalf("the writer kept %d bytes, want at most 8", got)
	}
}

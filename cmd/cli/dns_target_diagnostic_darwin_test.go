//go:build darwin

package cli

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestEnsureInterceptDNSTargetFailedDecision(t *testing.T) {
	for _, owned := range []bool{false, true} {
		name := "without target"
		if owned {
			name = "existing target"
		}
		t.Run(name, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			p.recoveryGen.Store(3)
			p.networkAcceptedGen.Store(7)
			if owned {
				persistInterceptTargetForTest(t, p, "Wi-Fi", "127.0.0.53")
				h.dns["Wi-Fi"] = []string{"127.0.0.53"}
			}
			before := p.interceptDNSTargetOwnershipLocked()
			fileBefore, _ := os.ReadFile(h.statePath)
			// This is the first mutating call in the no-target path. Replacing it
			// with a fatal stub makes any failure-to-absence regression safe/red.
			save := interceptSaveCurrentStaticDNSFn
			interceptSaveCurrentStaticDNSFn = func(*net.Interface) error { t.Fatal("discovery failure attempted a DNS backup"); return nil }
			// Exercise the production getoption/getpacket wrapper, not a synthetic
			// error. PATH contains only our fixture so no host ipconfig can run.
			binDir := t.TempDir()
			const script = `#!/bin/sh
case "$*" in
  'getoption en1 domain_name_server') code=17 ;;
  'getpacket en1') code=19 ;;
  *) exit 99 ;;
esac
printf 'private.example command output\n'
printf 'private.example command stderr\n' >&2
exit "$code"
`
			if err := os.WriteFile(filepath.Join(binDir, "ipconfig"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binDir)
			dhcpStub := interceptDHCPNameserversForInterfaceFn
			interceptDHCPNameserversForInterfaceFn = func(iface string) ([]string, error) {
				servers, err := ctrld.DHCPNameserversForInterface(iface)
				h.dhcpErr = err
				return servers, err
			}
			for range 4 {
				p.ensureInterceptDNSTarget([]string{})
			}
			wrapped, ok := h.dhcpErr.(interface{ Unwrap() []error })
			if !ok || len(wrapped.Unwrap()) != 2 {
				t.Fatalf("DHCP error did not preserve both command causes: %v", h.dhcpErr)
			}
			for i, cause := range wrapped.Unwrap() {
				var exitErr *exec.ExitError
				if !errors.As(cause, &exitErr) || exitErr.ExitCode() != []int{17, 19}[i] {
					t.Fatalf("command cause %d = %v, want original exit error", i, cause)
				}
				if !strings.Contains(string(exitErr.Stderr), "private.example") {
					t.Fatal("command fixture did not exercise private stderr")
				}
			}
			if got := dnsTargetReadErrorClass(h.dhcpErr); got != "command_failed" {
				t.Fatalf("production DHCP error class = %q", got)
			}
			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
				t.Fatal("failed discovery mutated DNS")
			}
			if p.interceptDNSTargetOwnershipLocked() != before {
				t.Fatal("failed discovery changed ownership")
			}
			fileAfter, _ := os.ReadFile(h.statePath)
			if !slices.Equal(fileBefore, fileAfter) {
				t.Fatal("failed discovery changed persisted ownership")
			}
			failed := oneRecoveryEvent(t, logs, dnsTargetFailedMessage)
			wantField(t, failed, "stage", "dhcp_dns")
			wantField(t, failed, "error_class", "command_failed")
			wantField(t, failed, "ownership_before", owned)
			wantField(t, failed, "ownership_after", owned)
			wantField(t, failed, "action", "unchanged")
			wantField(t, failed, "service", "Wi-Fi")
			wantField(t, failed, "interface", "en1")
			wantField(t, failed, "journal", true)
			detail := jsonLogEvents(t, logs, `intercept DNS target: could not read DHCP DNS for default-route service "Wi-Fi"`)
			if len(detail) != 4 {
				t.Fatal("detailed discovery errors disappeared from the debug stream")
			}
			wantField(t, detail[0], "level", "debug")
			wantField(t, detail[0], "error", h.dhcpErr.Error())

			// Successful empty discovery is different from failure: only now may
			// ctrld install the loopback target (or keep an existing one).
			interceptSaveCurrentStaticDNSFn = save
			interceptDHCPNameserversForInterfaceFn = dhcpStub
			h.dhcpErr = nil
			p.recoveryGen.Store(4)
			p.networkAcceptedGen.Store(8)
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			resolved := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
			wantField(t, resolved, "error_class", "command_failed")
			for _, event := range []map[string]any{failed, resolved} {
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				for _, raw := range []string{"error reading DHCP", "getoption", "getpacket", "exit status", "private.example"} {
					if strings.Contains(string(encoded), raw) {
						t.Fatalf("raw command error/output leaked into decision diagnostic: %s", encoded)
					}
				}
				if _, ok := event["error"]; ok {
					t.Fatal("decision diagnostic included a raw error field")
				}
			}
			wantField(t, resolved, "reason", "dns_less_network")
			wantField(t, resolved, "repeat_count", float64(3))
			wantField(t, resolved, "failure_recovery_generation", float64(3))
			wantField(t, resolved, "failure_transition_id", float64(7))
			wantField(t, resolved, "recovery_generation", float64(4))
			wantField(t, resolved, "transition_id", float64(8))
			wantField(t, resolved, "ownership_before", owned)
			wantField(t, resolved, "ownership_after", true)
			action := "set"
			if owned {
				action = "unchanged"
			}
			wantField(t, resolved, "action", action)
			wantSets := 1
			if owned {
				wantSets = 0
			}
			if len(h.setCalls) != wantSets || len(h.resetCalls) != 0 {
				t.Fatalf("set/reset = %v/%v", h.setCalls, h.resetCalls)
			}
			if !slices.Equal(h.dns["Wi-Fi"], []string{"127.0.0.53"}) {
				t.Fatal("empty discovery did not preserve a target")
			}

			// DHCP IPv4 arriving later must still remove it exactly once.
			h.dhcp = []string{"192.0.2.1"}
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			if len(h.resetCalls) != 1 || p.interceptDNSTargetService != "" {
				t.Fatal("later IPv4 DNS did not remove target once")
			}
		})
	}
}

func TestEnsureInterceptDNSTargetFailureThenIPv4(t *testing.T) {
	for _, static := range []bool{false, true} {
		name := "dhcp"
		if static {
			name = "static"
		}
		t.Run(name, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			persistInterceptTargetForTest(t, p, "Wi-Fi", "127.0.0.53")
			h.dns["Wi-Fi"] = []string{"127.0.0.53"}
			h.dhcpErr = errors.New("failed read")
			p.ensureInterceptDNSTarget([]string{})
			h.dhcpErr = nil
			h.dhcp = []string{"192.0.2.1"}
			reason := "dhcp_ipv4_dns"
			if static {
				h.dns["Wi-Fi"] = []string{"192.0.2.1"}
				reason = "static_ipv4_dns"
			}
			p.ensureInterceptDNSTarget([]string{})
			resolved := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
			wantField(t, resolved, "reason", reason)
			wantField(t, resolved, "action", "removed")
			wantField(t, resolved, "ownership_before", true)
			wantField(t, resolved, "ownership_after", false)
			if static && !slices.Equal(h.dns["Wi-Fi"], []string{"192.0.2.1"}) {
				t.Fatal("external static DNS was changed")
			}
		})
	}
}

func TestEnsureInterceptDNSTargetDiscoveryFailureStages(t *testing.T) {
	for _, stage := range []string{"system_discovery", "default_route", "interface_lookup", "service_lookup", "static_dns"} {
		t.Run(stage, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			input := []string{}
			err := errors.New("synthetic read error")
			switch stage {
			case "system_discovery":
				input = nil
			case "default_route":
				interceptDefaultRouteInterfaceFn = func() (string, error) { return "", err }
			case "interface_lookup":
				interceptInterfaceByNameFn = func(string) (*net.Interface, error) { return nil, err }
			case "service_lookup":
				interceptPatchNetIfaceNameFn = func(*net.Interface) (bool, error) { return false, err }
			case "static_dns":
				h.readErr = err
			}
			interceptSaveCurrentStaticDNSFn = func(*net.Interface) error { t.Fatal("failed discovery attempted backup"); return nil }
			p.ensureInterceptDNSTarget(input)
			p.ensureInterceptDNSTarget(input)
			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
				t.Fatal("failed discovery mutated DNS")
			}
			wantField(t, oneRecoveryEvent(t, logs, dnsTargetFailedMessage), "stage", stage)
		})
	}
}

func TestEnsureInterceptDNSTargetResolutionDoesNotClaimWriteSuccess(t *testing.T) {
	logs := captureDebugMainLog(t)
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	h.dhcpErr = errors.New("read failed")
	p.ensureInterceptDNSTarget([]string{})
	h.dhcpErr = nil
	h.setErr = errors.New("synthetic set failure")
	p.ensureInterceptDNSTarget([]string{})
	event := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
	wantField(t, event, "outcome", "decision_available")
	wantField(t, event, "reason", "dns_less_network")
	wantField(t, event, "action", "unchanged")
	wantField(t, event, "ownership_before", false)
	wantField(t, event, "ownership_after", false)
	if len(h.setCalls) != 1 || p.interceptDNSTargetService != "" {
		t.Fatal("failed target write was not exercised or acquired ownership")
	}
}

func TestEnsureInterceptDNSTargetSamplesCorrelationBeforeRead(t *testing.T) {
	logs := captureDebugMainLog(t)
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	p.recoveryGen.Store(2)
	p.networkAcceptedGen.Store(5)
	interceptDHCPNameserversForInterfaceFn = func(string) ([]string, error) {
		p.recoveryGen.Store(3)
		p.networkAcceptedGen.Store(6)
		return nil, errors.New("read failed")
	}
	p.ensureInterceptDNSTarget([]string{})
	event := oneRecoveryEvent(t, logs, dnsTargetFailedMessage)
	wantField(t, event, "recovery_generation", float64(2))
	wantField(t, event, "transition_id", float64(5))
	if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
		t.Fatal("failed discovery mutated DNS")
	}
}

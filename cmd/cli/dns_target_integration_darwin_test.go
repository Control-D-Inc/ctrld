//go:build darwin

package cli

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNativeCLATDecisionJournalIntegration(t *testing.T) {
	for _, local := range []bool{false, true} {
		name := "target installed"
		if local {
			name = "local resolver preserved"
		}
		t.Run(name, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			h.dhcpErr = errors.New("no DHCP packet")
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			wantField(t, oneRecoveryEvent(t, logs, dnsTargetFailedMessage), "stage", "dhcp_dns")
			h.nativeCLAT = true
			reason := "dns_less_network"
			action := "set"
			if local {
				h.dns["Wi-Fi"] = []string{"::1"}
				reason = "static_loopback_dns"
				action = "unchanged"
			}
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			event := oneRecoveryEvent(t, logs, dnsTargetResolvedMessage)
			wantField(t, event, "reason", reason)
			wantField(t, event, "action", action)
			wantField(t, event, "repeat_count", float64(1))
			if p.dnsInterceptState.(*pfState).targetDiagnostic.pending {
				t.Fatal("native decision left stale failure")
			}
			if local && (len(h.setCalls) != 0 || len(h.resetCalls) != 0 || h.dns["Wi-Fi"][0] != "::1") {
				t.Fatal("local resolver changed")
			}
			if !local && len(h.setCalls) != 1 {
				t.Fatal("native target not installed exactly once")
			}
		})
	}
}

func TestNativeCLATRecheckFailureJournal(t *testing.T) {
	for _, static := range []bool{false, true} {
		name := "native recheck"
		if static {
			name = "static recheck"
		}
		t.Run(name, func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			h.dhcpErr = errors.New("no DHCP packet")
			h.nativeCLAT = true
			p := newInterceptTargetProg()
			stage := "native_recheck"
			calls := 0
			if static {
				stage = "static_recheck"
				orig := interceptNativeStaticDNSFn
				interceptNativeStaticDNSFn = func(ctx context.Context, i *net.Interface) ([]string, error) {
					calls++
					if calls%2 == 0 {
						return nil, context.DeadlineExceeded
					}
					return orig(ctx, i)
				}
			} else {
				orig := interceptNativeCLATDefaultServiceFn
				interceptNativeCLATDefaultServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
					calls++
					if calls%2 == 0 {
						return nativeTargetService{}, context.DeadlineExceeded
					}
					return orig(ctx, device)
				}
			}
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			event := oneRecoveryEvent(t, logs, dnsTargetFailedMessage)
			wantField(t, event, "stage", stage)
			wantField(t, event, "error_class", "timeout")
			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 {
				t.Fatal("failed recheck changed DNS")
			}
		})
	}
}

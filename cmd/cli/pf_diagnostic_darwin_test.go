//go:build darwin

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func stubPFDiagnosticCapture(t *testing.T) *int {
	t.Helper()
	old := capturePFDiagnosticFn
	t.Cleanup(func() { capturePFDiagnosticFn = old })
	calls := 0
	capturePFDiagnosticFn = func() pfDiagnosticSnapshot {
		calls++
		s := parsePFDiagnostic([]byte(pfDiagnosticFixture))
		s.RouteV4, s.RouteV6, s.AddressCode = "en0", "en0", "ok"
		s.CLAT = true
		return s
	}
	return &calls
}

// Exercise the production probe -> diagnostic handoff, without executing a PF
// command or sending DNS. Removing that handoff must make this test fail.
func TestPFDiagnosticProbeWiringAndPrivacy(t *testing.T) {
	logs := captureTransitionLogs(t)
	reads := stubPFDiagnosticCapture(t)
	old := pfProbeNameservers
	t.Cleanup(func() { pfProbeNameservers = old; pfProbeLogs = pfProbeLogState{} })
	pfProbeNameservers = func() []string { return []string{"[fe80::1%en0]:53", "76.76.2.0:53"} }
	p := &prog{dnsInterceptState: &pfState{}}
	p.recoveryGen.Store(7)

	p.probePFIntercept()
	p.probePFIntercept()
	p.logPFIPv6Diagnostic(pfProbeObservation{result: pfProbeIntercepted, recoveryGeneration: 7, stage: "received", target: "192.0.2.1:53"}, "ipv4")
	p.logPFIPv6Diagnostic(pfProbeObservation{result: pfProbeIntercepted}, "ipv4")
	var events []map[string]any
	for _, line := range strings.Split(logs.String(), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil || e["message"] != "DNS intercept IPv6 block diagnostic" {
			continue
		}
		events = append(events, e)
		for _, forbidden := range []string{"_pf-probe", "Owner", "Inserted", "Bytes:", "from any", "probe_id", "client_address"} {
			if strings.Contains(line, forbidden) {
				t.Fatalf("raw payload escaped: %s", forbidden)
			}
		}
		if e["counter_scope"] != "shared_traffic_not_probe_attribution" || e["ipv6_dns_udp_packets"] != float64(812) || e["recovery_generation"] != float64(7) {
			t.Fatalf("missing evidence: %v", e)
		}
	}
	if *reads != 1 || len(events) != 2 {
		t.Fatalf("reads=%d events=%v", *reads, events)
	}
	if events[0]["outcome"] != "indeterminate" || events[1]["outcome"] != "intercepted" || events[1]["capture_cached"] != true {
		t.Fatalf("missing restore: %v", events)
	}
}

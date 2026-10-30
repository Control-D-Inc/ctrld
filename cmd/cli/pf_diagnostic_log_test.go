package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPFDiagnosticLogAllowlist(t *testing.T) {
	for _, code := range []string{"ok", "read_failed", "partial_or_malformed"} {
		t.Run(code, func(t *testing.T) {
			s := parsePFDiagnostic([]byte(pfDiagnosticFixture))
			s.Code, s.AddressCode = code, "read_failed"
			if code != "ok" {
				s.UDP.Known, s.TCP.Known = false, false
			}
			e := pfDiagnosticEvent{Snapshot: s, Generation: 3, UDPDeltaCode: "unknown", TCPDeltaCode: "unknown",
				Observation: pfProbeObservation{result: pfProbeNotIntercepted, probeID: "private-query.invalid", target: "192.0.2.1:53", recoveryGeneration: 7, stage: "delivery", code: "timeout"}}
			output := captureDebugMainLog(t)
			logPFDiagnostic(e, "ipv4")
			line := strings.TrimSpace(output.String())
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"private-query", "probe_id", "Owner", "Inserted", "from any", "Bytes:"} {
				if strings.Contains(line, forbidden) {
					t.Fatalf("raw payload escaped: %s", forbidden)
				}
			}
			if event["pf_read_status"] != code || event["probe_transport"] != "udp4" || event["capture_generation"] != float64(3) || event["recovery_generation"] != float64(7) || event["counter_scope"] != "shared_traffic_not_probe_attribution" {
				t.Fatalf("missing evidence: %v", event)
			}
			for _, field := range []string{"ipv6_dns_udp_packets", "ipv6_dns_tcp_packets"} {
				_, exists := event[field]
				if exists != (code == "ok") {
					t.Fatalf("unknown counters serialized as zero: %v", event)
				}
			}
			for _, field := range []string{"ipv6_dns_udp_packet_delta", "ipv6_dns_tcp_packet_delta", "clat_address_present", "native_ipv4_on_default_interface"} {
				if _, exists := event[field]; exists {
					t.Fatalf("unknown evidence serialized: %s", field)
				}
			}
		})
	}
}

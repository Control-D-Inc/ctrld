package cli

import ctrld "github.com/Control-D-Inc/ctrld"

func logPFDiagnosticRule(e *ctrld.LogEvent, id string, r pfDiagnosticRuleCount, delta uint64, deltaCode string) {
	// false means this exact rule was not observed, not proof no IPv6 block exists.
	e.Bool(id+"_rule_observed", r.Installed).Bool(id+"_counter_known", r.Known)
	if r.Known {
		e.Uint64(id+"_packets", r.Packets)
	}
	e.Str(id+"_delta_status", deltaCode)
	if deltaCode == "shared_traffic" {
		e.Uint64(id+"_packet_delta", delta)
	}
}

func logPFDiagnostic(e pfDiagnosticEvent, family string) {
	o := e.Observation
	s := e.Snapshot
	// Recovery generation and target associate this snapshot with the existing
	// probe-result event without repeating the probe's DNS query name.
	probeFamily := "none"
	if o.stage != "target" && o.target != "" && family == "ipv4" {
		probeFamily = "udp4"
	}
	log := mainLog.Load().Debug().
		Uint64("capture_generation", e.Generation).
		Int64("capture_age_ms", e.Age.Milliseconds()).Bool("capture_cached", e.Cached).
		Uint64("recovery_generation", o.recoveryGeneration).
		Str("resolver_target", o.target).Str("resolver_family", family).
		Str("probe_transport", probeFamily).Str("outcome", o.result.String()).
		Str("stage", o.stage).Str("probe_error_code", o.code).
		Str("pf_read_status", s.Code).
		Str("counter_scope", "shared_traffic_not_probe_attribution").
		Str("default_route_v4_interface", s.RouteV4).
		Str("default_route_v6_interface", s.RouteV6).
		Str("address_status", s.AddressCode)
	if s.AddressCode == "ok" || s.AddressCode == "default_v4_unavailable" {
		log.Bool("clat_address_present", s.CLAT)
	}
	if s.AddressCode == "ok" {
		log.Bool("native_ipv4_on_default_interface", s.NativeIPv4)
	}
	logPFDiagnosticRule(log, "ipv6_dns_udp", s.UDP, e.UDPDelta, e.UDPDeltaCode)
	logPFDiagnosticRule(log, "ipv6_dns_tcp", s.TCP, e.TCPDelta, e.TCPDeltaCode)
	log.Msg("DNS intercept IPv6 block diagnostic")
}

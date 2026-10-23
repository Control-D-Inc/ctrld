//go:build darwin

package cli

import (
	"context"
	"os/exec"
	"time"
)

// This is the only command added by diagnostics: read only the exact ctrld
// anchor, never recurse or dump system rules/states. Tests replace this seam
// before driving the real probe, including on privileged native runners.
var capturePFDiagnosticFn = capturePFDiagnostic

func capturePFDiagnostic() pfDiagnosticSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), pfDiagnosticTimeout)
	defer cancel()
	s := runPFDiagnosticCommand(ctx, exec.CommandContext(ctx, "/sbin/pfctl", "-a", pfAnchorName, "-vvsr"))
	v4, v6 := defaultRoutesFn()
	s.RouteV4, s.RouteV6 = v4.Interface, v6.Interface
	state, err := readNetworkSourceStateFn()
	s.AddressCode = "read_failed"
	if err == nil && state != nil {
		s.CLAT = dns64StateHasCLAT(state)
		s.AddressCode = "default_v4_unavailable"
		if iface, ok := state.Interface[v4.Interface]; ok && iface.Interface != nil && iface.IsUp() {
			s.AddressCode = "ok"
			for _, prefix := range state.InterfaceIPs[v4.Interface] {
				addr := prefix.Addr().Unmap()
				if addr.Is4() && !clatPrefix.Contains(addr) && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsUnspecified() && !addr.IsMulticast() {
					s.NativeIPv4 = true
				}
			}
		}
	}
	return s
}

func (p *prog) logPFIPv6Diagnostic(o pfProbeObservation, family string) {
	state, ok := p.dnsInterceptState.(*pfState)
	if !ok || state == nil {
		return
	}
	e, emit := state.ipv6Diagnostic.observe(time.Now(), o, capturePFDiagnosticFn)
	if !emit {
		return
	}
	logPFDiagnostic(e, family)
}

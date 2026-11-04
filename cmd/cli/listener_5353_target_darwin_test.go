//go:build darwin

package cli

import (
	"errors"
	"slices"
	"testing"
)

func TestNativeCLATCustomListener5353Lifecycle(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.53", "192.0.2.10"} {
		t.Run(ip, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.nativeCLAT = true
			h.dhcpErr = errors.New("DHCPv4 intentionally absent")
			p := newInterceptTargetProg()
			p.cfg.Listener["0"].IP = ip
			p.cfg.Listener["0"].Port = 5353
			target := p.interceptDNSTargetValue()
			p.ensureInterceptDNSTarget([]string{})
			p.ensureInterceptDNSTarget([]string{})
			if !slices.Equal(h.dns["Wi-Fi"], []string{target}) || len(h.setCalls) != 1 {
				t.Fatalf("target was not installed idempotently: %v writes %v", h.dns, h.setCalls)
			}
			if target == ip {
				t.Fatal("OS DNS would hit port53 at listener instead of PF port5353 redirect")
			}
			h.dhcpErr = nil
			h.dhcp = []string{"192.0.2.53"}
			h.nativeCLAT = false
			p.ensureInterceptDNSTarget([]string{"192.0.2.53"})
			if len(h.dns["Wi-Fi"]) != 0 || p.interceptDNSTargetService != "" {
				t.Fatalf("DHCP return failed to remove target: %+v", h.dns)
			}
			if p.cfg.Listener["0"].IP != ip || p.cfg.Listener["0"].Port != 5353 {
				t.Fatal("target lifecycle changed configured listener")
			}
		})
	}
}

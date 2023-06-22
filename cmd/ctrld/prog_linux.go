package main

import (
	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/dns"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

func init() {
	if r, err := dns.NewOSConfigurator(logf, "lo"); err == nil {
		useSystemdResolved = r.Mode() == "systemd-resolved"
	}
}

func (p *prog) preRun() {
	if !service.Interactive() {
		p.setDNS()
	}
}

func setDependencies(svc *service.Config) {
	svc.Dependencies = []string{
		"Wants=network-online.target",
		"After=network-online.target",
		"Wants=NetworkManager-wait-online.service",
		"After=NetworkManager-wait-online.service",
	}
	// On EdeOS, ctrld needs to start after vyatta-dhcpd, so it can read leases file.
	if router.Name() == router.EdgeOS {
		svc.Dependencies = append(svc.Dependencies, "Wants=vyatta-dhcpd.service")
		svc.Dependencies = append(svc.Dependencies, "After=vyatta-dhcpd.service")
		svc.Dependencies = append(svc.Dependencies, "Wants=dnsmasq.service")
		svc.Dependencies = append(svc.Dependencies, "After=dnsmasq.service")
	}
	// On Firewalla, ctrld needs to start after firerouter_{dhcp,dns}, so it can read leases file.
	if router.Name() == router.Firewalla {
		svc.Dependencies = append(svc.Dependencies, "Wants=firerouter_dhcp.service")
		svc.Dependencies = append(svc.Dependencies, "After=firerouter_dhcp.service")
		svc.Dependencies = append(svc.Dependencies, "Wants=firerouter_dns.service")
		svc.Dependencies = append(svc.Dependencies, "After=firerouter_dns.service")
	}
}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}

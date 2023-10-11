package cli

import (
	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld/internal/dns"
)

func init() {
	if r, err := dns.NewOSConfigurator(func(format string, args ...any) {}, "lo"); err == nil {
		useSystemdResolved = r.Mode() == "systemd-resolved"
	}
}

func setDependencies(svc *service.Config) {
	svc.Dependencies = []string{
		"Wants=network-online.target",
		"After=network-online.target",
		"Wants=NetworkManager-wait-online.service",
		"After=NetworkManager-wait-online.service",
		"Wants=systemd-networkd-wait-online.service",
		"After=systemd-networkd-wait-online.service",
		"Wants=nss-lookup.target",
		"After=nss-lookup.target",
	}
}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}

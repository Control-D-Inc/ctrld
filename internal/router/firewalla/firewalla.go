package firewalla

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"

	"github.com/Control-D-Inc/ctrld"
	"github.com/kardianos/service"
)

const (
	Name = "firewalla"

	firewallaDNSMasqConfigPath   = "/home/pi/.firewalla/config/dnsmasq_local/ctrld"
	firewallaConfigPostMainDir   = "/home/pi/.firewalla/config/post_main.d"
	firewallaCtrldInitScriptPath = "/home/pi/.firewalla/config/post_main.d/start_ctrld.sh"
)

type Firewalla struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Firewalla routers.
func New(cfg *ctrld.Config) *Firewalla {
	return &Firewalla{cfg: cfg}
}

func (f *Firewalla) ConfigureService(_ *service.Config) error {
	return nil
}

func (f *Firewalla) Install(_ *service.Config) error {
	// Writing startup script.
	if err := writeFirewallStartupScript(); err != nil {
		return fmt.Errorf("writing startup script: %w", err)
	}
	return nil
}

func (f *Firewalla) Uninstall(_ *service.Config) error {
	// Removing startup script.
	if err := os.Remove(firewallaCtrldInitScriptPath); err != nil {
		return fmt.Errorf("removing startup script: %w", err)
	}
	return nil
}

func (f *Firewalla) PreRun() error {
	return nil
}

func (f *Firewalla) Setup() error {
	if f.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	data, err := dnsmasq.FirewallaConfTmpl(dnsmasq.ConfigContentTmpl, f.cfg)
	if err != nil {
		return fmt.Errorf("generating dnsmasq config: %w", err)
	}
	if err := os.WriteFile(firewallaDNSMasqConfigPath, []byte(data), 0600); err != nil {
		return fmt.Errorf("writing ctrld config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("restartDNSMasq: %w", err)
	}

	return nil
}

func (f *Firewalla) Cleanup() error {
	if f.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Removing current config.
	if err := os.Remove(firewallaDNSMasqConfigPath); err != nil {
		return fmt.Errorf("removing ctrld config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("restartDNSMasq: %w", err)
	}

	return nil
}

func writeFirewallStartupScript() error {
	if err := os.MkdirAll(firewallaConfigPostMainDir, 0775); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// This is called when "ctrld start ..." runs, so recording
	// the same command line arguments to use in startup script.
	argStr := strings.Join(os.Args[1:], " ")
	script := fmt.Sprintf("#!/bin/bash\n\nsudo %q %s\n", exe, argStr)
	return os.WriteFile(firewallaCtrldInitScriptPath, []byte(script), 0755)
}

func restartDNSMasq() error {
	return exec.Command("systemctl", "restart", "firerouter_dns").Run()
}

package synology

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"

	"github.com/Control-D-Inc/ctrld"
	"github.com/kardianos/service"
)

const (
	Name = "synology"

	synologyDNSMasqConfigPath = "/etc/dhcpd/dhcpd-zzz-ctrld.conf"
	synologyDhcpdInfoPath     = "/etc/dhcpd/dhcpd-zzz-ctrld.info"
)

type Synology struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Ubios routers.
func New(cfg *ctrld.Config) *Synology {
	return &Synology{cfg: cfg}
}

func (s *Synology) ConfigureService(config *service.Config) error {
	return nil
}

func (s *Synology) Install(_ *service.Config) error {
	return nil
}

func (s *Synology) Uninstall(_ *service.Config) error {
	return nil
}

func (s *Synology) PreRun() error {
	return nil
}

func (s *Synology) Setup() error {
	if s.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, s.cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(synologyDNSMasqConfigPath, []byte(data), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(synologyDhcpdInfoPath, []byte(`enable="yes"`), 0600); err != nil {
		return err
	}
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (s *Synology) Cleanup() error {
	if s.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Remove the custom config files.
	for _, f := range []string{synologyDNSMasqConfigPath, synologyDhcpdInfoPath} {
		if err := os.Remove(f); err != nil {
			return err
		}
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func restartDNSMasq() error {
	if out, err := exec.Command("/etc/rc.network", "nat-restart-dhcp").CombinedOutput(); err != nil {
		return fmt.Errorf("synologyRestartDNSMasq: %s - %w", string(out), err)
	}
	return nil
}

package synology

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kardianos/service"
	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
)

const (
	Name = "synology"

	synologyDNSMasqConfigPath = "/etc/dhcpd/dhcpd-zzz-ctrld.conf"
	synologyDhcpdInfoPath     = "/etc/dhcpd/dhcpd-zzz-ctrld.info"
)

type Synology struct {
	cfg        *ctrld.Config
	useUpstart bool
}

// New returns a router.Router for configuring/setup/run ctrld on Ubios routers.
func New(cfg *ctrld.Config) *Synology {
	return &Synology{
		cfg:        cfg,
		useUpstart: service.Platform() == "linux-upstart",
	}
}

func (s *Synology) ConfigureService(svc *service.Config) error {
	svc.Option["LogOutput"] = true
	return nil
}

func (s *Synology) Install(_ *service.Config) error {
	return nil
}

func (s *Synology) Uninstall(_ *service.Config) error {
	return nil
}

func (s *Synology) PreRun() error {
	if s.useUpstart {
		if err := ntp.WaitUpstart(); err != nil {
			return err
		}
		return waitDhcpServer()
	}
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

func waitDhcpServer() error {
	// Wait until `initctl status dhcpserver` returns running state.
	b := backoff.NewBackoff("waitDhcpServer", func(format string, args ...any) {}, 10*time.Second)
	for {
		out, err := exec.Command("initctl", "status", "dhcpserver").CombinedOutput()
		if err != nil {
			if strings.Contains(err.Error(), "Unknown job") {
				// dhcpserver service does not exist.
				return nil
			}
			return fmt.Errorf("exec.Command: %w", err)
		}
		if bytes.Contains(out, []byte("start/running")) {
			return nil
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}

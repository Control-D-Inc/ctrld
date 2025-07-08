package ubios

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/edgeos"
)

const Name = "ubios"

type Ubios struct {
	cfg             *ctrld.Config
	dnsmasqConfPath string
}

// New returns a router.Router for configuring/setup/run ctrld on Ubios routers.
func New(cfg *ctrld.Config) *Ubios {
	return &Ubios{
		cfg:             cfg,
		dnsmasqConfPath: filepath.Join(dnsmasq.UbiosConfPath(), dnsmasq.UbiosConfName),
	}
}

func (u *Ubios) ConfigureService(config *service.Config) error {
	return nil
}

func (u *Ubios) Install(config *service.Config) error {
	// See comment in (*edgeos.EdgeOS).Install method.
	if edgeos.ContentFilteringEnabled() {
		return edgeos.ErrContentFilteringEnabled
	}
	// See comment in (*edgeos.EdgeOS).Install method.
	if edgeos.DnsShieldEnabled() {
		return edgeos.ErrDnsShieldEnabled
	}
	return nil
}

func (u *Ubios) Uninstall(_ *service.Config) error {
	return nil
}

func (u *Ubios) PreRun() error {
	return nil
}

func (u *Ubios) Setup() error {
	if u.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	data, err := dnsmasq.ConfTmplWithCacheDisabled(dnsmasq.ConfigContentTmpl, u.cfg, false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(u.dnsmasqConfPath, []byte(data), 0600); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (u *Ubios) Cleanup() error {
	if u.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Remove the custom dnsmasq config
	if err := os.Remove(u.dnsmasqConfPath); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func restartDNSMasq() error {
	buf, err := os.ReadFile(dnsmasq.UbiosPidFile())
	if err != nil {
		return err
	}
	pid, err := strconv.ParseUint(string(bytes.TrimSpace(buf)), 10, 64)
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return proc.Kill()
}

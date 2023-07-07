package ddwrt

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const Name = "ddwrt"

//lint:ignore ST1005 This error is for human.
var errDdwrtJffs2NotEnabled = errors.New(`could not install service without jffs, follow this guide to enable:

https://wiki.dd-wrt.com/wiki/index.php/Journalling_Flash_File_System
`)

var nvramKvMap = map[string]string{
	"dns_dnsmasq":     "1", // Make dnsmasq running but disable DNS ability, ctrld will replace it.
	"dnsmasq_options": "",  // Configuration of dnsmasq set by ctrld, filled by setupDDWrt.
	"dns_crypt":       "0", // Disable DNSCrypt.
	"dnssec":          "0", // Disable DNSSEC.
}

type Ddwrt struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on ddwrt routers.
func New(cfg *ctrld.Config) *Ddwrt {
	return &Ddwrt{cfg: cfg}
}

func (d *Ddwrt) ConfigureService(config *service.Config) error {
	if !ddwrtJff2Enabled() {
		return errDdwrtJffs2NotEnabled
	}
	return nil
}

func (d *Ddwrt) Install(_ *service.Config) error {
	return nil
}

func (d *Ddwrt) Uninstall(_ *service.Config) error {
	return nil
}

func (d *Ddwrt) PreRun() error {
	_ = d.Cleanup()
	return ntp.Wait()
}

func (d *Ddwrt) Setup() error {
	// Already setup.
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		return nil
	}

	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, d.cfg)
	if err != nil {
		return err
	}

	nvramKvMap["dnsmasq_options"] = data
	if err := nvram.SetKV(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (d *Ddwrt) Cleanup() error {
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		nvramKvMap["dnsmasq_options"] = ""
		// Restore old configs.
		if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
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
	if out, err := exec.Command("restart_dns").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dns: %s, %w", string(out), err)
	}
	return nil
}

func ddwrtJff2Enabled() bool {
	out, _ := nvram.Run("get", "enable_jffs2")
	return out == "1"
}

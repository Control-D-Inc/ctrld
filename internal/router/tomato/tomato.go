package tomato

import (
	"fmt"
	"os/exec"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
	"github.com/kardianos/service"
)

const (
	Name = "freshtomato"

	tomatoDnsCryptProxySvcName = "dnscrypt-proxy"
	tomatoStubbySvcName        = "stubby"
	tomatoDNSMasqSvcName       = "dnsmasq"
)

var nvramKvMap = map[string]string{
	"dnsmasq_custom": "",  // Configuration of dnsmasq set by ctrld, filled by setupTomato.
	"dnscrypt_proxy": "0", // Disable DNSCrypt.
	"dnssec_enable":  "0", // Disable DNSSEC.
	"stubby_proxy":   "0", // Disable Stubby
}

type FreshTomato struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Ubios routers.
func New(cfg *ctrld.Config) *FreshTomato {
	return &FreshTomato{cfg: cfg}
}

func (f *FreshTomato) ConfigureService(config *service.Config) error {
	return nil
}

func (f *FreshTomato) Install(_ *service.Config) error {
	return nil
}

func (f *FreshTomato) Uninstall(_ *service.Config) error {
	return nil
}

func (f *FreshTomato) PreRun() error {
	_ = f.Cleanup()
	return ntp.WaitNvram()
}

func (f *FreshTomato) Setup() error {
	if f.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Already setup.
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		return nil
	}

	data, err := dnsmasq.ConfTmpl(dnsmasq.ConfigContentTmpl, f.cfg)
	if err != nil {
		return err
	}
	nvramKvMap["dnsmasq_custom"] = data
	if err := nvram.SetKV(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	// Restart dnscrypt-proxy service.
	if err := tomatoRestartServiceWithKill(tomatoDnsCryptProxySvcName, true); err != nil {
		return err
	}
	// Restart stubby service.
	if err := tomatoRestartService(tomatoStubbySvcName); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func (f *FreshTomato) Cleanup() error {
	if f.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		nvramKvMap["dnsmasq_custom"] = ""
		// Restore old configs.
		if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
			return err
		}
	}

	// Restart dnscrypt-proxy service.
	if err := tomatoRestartServiceWithKill(tomatoDnsCryptProxySvcName, true); err != nil {
		return err
	}
	// Restart stubby service.
	if err := tomatoRestartService(tomatoStubbySvcName); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func tomatoRestartService(name string) error {
	return tomatoRestartServiceWithKill(name, false)
}

func tomatoRestartServiceWithKill(name string, killBeforeRestart bool) error {
	if killBeforeRestart {
		_, _ = exec.Command("killall", name).CombinedOutput()
	}
	if out, err := exec.Command("service", name, "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("service restart %s: %s, %w", name, string(out), err)
	}
	return nil
}

func restartDNSMasq() error {
	return tomatoRestartService(tomatoDNSMasqSvcName)
}

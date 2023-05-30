package router

import (
	"fmt"
	"os/exec"
)

const (
	tomatoDnsCryptProxySvcName = "dnscrypt-proxy"
	tomatoStubbySvcName        = "stubby"
	tomatoDNSMasqSvcName       = "dnsmasq"
)

func setupTomato() error {
	// Already setup.
	if val, _ := nvram("get", nvramCtrldSetupKey); val == "1" {
		return nil
	}

	data, err := dnsMasqConf()
	if err != nil {
		return err
	}

	nvramKvMap := nvramSetupKV()
	nvramKvMap["dnsmasq_custom"] = data
	if err := nvramSetKV(nvramKvMap, nvramCtrldSetupKey); err != nil {
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

func postInstallTomato() error {
	return nil
}

func cleanupTomato() error {
	// Restore old configs.
	if err := nvramRestore(nvramSetupKV(), nvramCtrldSetupKey); err != nil {
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

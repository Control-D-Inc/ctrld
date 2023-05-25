package router

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	synologyDNSMasqConfigPath = "/etc/dhcpd/dhcpd-zzz-ctrld.conf"
	synologyDhcpdInfoPath     = "/etc/dhcpd/dhcpd-zzz-ctrld.info"
)

func setupSynology() error {
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return err
	}
	if err := os.WriteFile(synologyDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
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

func cleanupSynology() error {
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

func postInstallSynology() error {
	return nil
}

func synologyRestartDNSMasq() error {
	if out, err := exec.Command("/etc/rc.network", "nat-restart-dhcp").CombinedOutput(); err != nil {
		return fmt.Errorf("synologyRestartDNSMasq: %s - %w", string(out), err)
	}
	return nil
}

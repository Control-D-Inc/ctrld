package router

import (
	"fmt"
	"os"
	"os/exec"
)

const edgeOSDNSMasqConfigPath = "/etc/dnsmasq.d/dnsmasq-zzz-ctrld.conf"

func setupEdgeOS() error {
	// Disable dnsmasq as DNS server.
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return err
	}
	if err := os.WriteFile(edgeOSDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func cleanupEdgeOS() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(edgeOSDNSMasqConfigPath); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallEdgeOS() error {
	return nil
}

func edgeOSRestartDNSMasq() error {
	if out, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("edgeosRestartDNSMasq: %s, %w", string(out), err)
	}
	return nil
}

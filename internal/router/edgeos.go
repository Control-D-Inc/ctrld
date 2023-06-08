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
	// If "Content Filtering" is enabled, UniFi OS will create firewall rules to intercept all DNS queries
	// from outside, and route those queries to separated interfaces (e.g: dnsfilter-2@if79) created by UniFi OS.
	// Thus, those queries will never reach ctrld listener. UniFi OS does not provide any mechanism to toggle this
	// feature via command line, so there's nothing ctrld can do to disable this feature. For now, reporting an
	// error and guiding users to disable the feature using UniFi OS web UI.
	if contentFilteringEnabled() {
		return errContentFilteringEnabled
	}
	return nil
}

func edgeOSRestartDNSMasq() error {
	if out, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("edgeosRestartDNSMasq: %s, %w", string(out), err)
	}
	return nil
}

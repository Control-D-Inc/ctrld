package router

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	firewallaDNSMasqConfigPath       = "/home/pi/.firewalla/config/dnsmasq_local"
	firewallaDNSMasqBackupConfigPath = "/home/pi/.firewalla/config/dnsmasq_local.bak"
	firewallaConfigPostMainDir       = "/home/pi/.firewalla/config/post_main.d"
	firewallaCtrldInitScriptPath     = "/home/pi/.firewalla/config/post_main.d/start_ctrld.sh"
)

func setupFirewalla() error {
	fi, err := os.Stat(firewallaDNSMasqConfigPath)
	if err != nil {
		return fmt.Errorf("setupFirewalla: get current config directory: %w", err)
	}

	_ = os.RemoveAll(firewallaDNSMasqBackupConfigPath)

	// Creating a backup.
	if err := os.Rename(firewallaDNSMasqConfigPath, firewallaDNSMasqBackupConfigPath); err != nil {
		return fmt.Errorf("setupFirewalla: backup current config: %w", err)
	}

	// Creating our own config.
	if err := os.MkdirAll(firewallaDNSMasqConfigPath, fi.Mode()); err != nil {
		return fmt.Errorf("setupFirewalla: creating config dir: %w", err)
	}

	// Adding ctrld listener as the only upstream.
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return fmt.Errorf("setupFirewalla: generating dnsmasq config: %w", err)
	}
	ctrldConfPath := filepath.Join(firewallaDNSMasqConfigPath, "ctrld")
	if err := os.WriteFile(ctrldConfPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return fmt.Errorf("setupFirewalla: writing ctrld config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupFirewalla: restartDNSMasq: %w", err)
	}

	return nil
}

func cleanupFirewalla() error {
	// Do nothing if there's no backup config.
	if _, err := os.Stat(firewallaDNSMasqBackupConfigPath); err != nil && os.IsNotExist(err) {
		return nil
	}

	// Removing current config.
	if err := os.RemoveAll(firewallaDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupFirewalla: removing ctrld config: %w", err)
	}

	// Restoring backup.
	if err := os.Rename(firewallaDNSMasqBackupConfigPath, firewallaDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupFirewalla: restoring backup config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleaupFirewalla: restartDNSMasq: %w", err)
	}

	return nil
}

func postInstallFirewalla() error {
	// Writing startup script.
	if err := writeFirewallStartupScript(); err != nil {
		return fmt.Errorf("postInstallFirewalla: writing startup script: %w", err)
	}
	return nil
}

func firewallaRestartDNSMasq() error {
	return exec.Command("systemctl", "restart", "firerouter_dns").Run()
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

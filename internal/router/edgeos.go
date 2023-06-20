package router

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	edgeOSDNSMasqConfigPath    = "/etc/dnsmasq.d/dnsmasq-zzz-ctrld.conf"
	UsgDNSMasqConfigPath       = "/etc/dnsmasq.conf"
	UsgDNSMasqBackupConfigPath = "/etc/dnsmasq.conf.bak"
)

var (
	isUSG bool
)

func setupEdgeOS() error {
	if isUSG {
		return setupUSG()
	}
	return setupUDM()
}

func setupUDM() error {
	// Disable dnsmasq as DNS server.
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return fmt.Errorf("setupUDM: generating dnsmasq config: %w", err)
	}
	if err := os.WriteFile(edgeOSDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return fmt.Errorf("setupUDM: generating dnsmasq config: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupUDM: restartDNSMasq: %w", err)
	}
	return nil
}

func setupUSG() error {
	// On USG, dnsmasq is configured to forward queries to external provider by default.
	// So instead of generating config in /etc/dnsmasq.d, we need to create a backup of
	// the config, then modify it to forward queries to ctrld listener.

	// Creating a backup.
	buf, err := os.ReadFile(UsgDNSMasqConfigPath)
	if err != nil {
		return fmt.Errorf("setupUSG: reading current config: %w", err)
	}
	if err := os.WriteFile(UsgDNSMasqBackupConfigPath, buf, 0600); err != nil {
		return fmt.Errorf("setupUSG: backup current config: %w", err)
	}

	// Removing all configured upstreams.
	var sb strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "server=") {
			continue
		}
		if strings.HasPrefix(line, "all-servers") {
			continue
		}
		sb.WriteString(line)
	}

	// Adding ctrld listener as the only upstream.
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return fmt.Errorf("setupUSG: generating dnsmasq config: %w", err)
	}
	sb.WriteString("\n")
	sb.WriteString(dnsMasqConfigContent)
	if err := os.WriteFile(UsgDNSMasqConfigPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("setupUSG: writing dnsmasq config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupUSG: restartDNSMasq: %w", err)
	}
	return nil
}

func cleanupEdgeOS() error {
	if isUSG {
		return cleanupUSG()
	}
	return cleanupUDM()
}

func cleanupUDM() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(edgeOSDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupUDM: os.Remove: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleanupUDM: restartDNSMasq: %w", err)
	}
	return nil
}

func cleanupUSG() error {
	if err := os.Rename(UsgDNSMasqBackupConfigPath, UsgDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupUSG: os.Rename: %w", err)
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleanupUSG: restartDNSMasq: %w", err)
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

package router

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	firewallaDNSMasqConfigPath   = "/home/pi/.firewalla/config/dnsmasq_local/ctrld"
	firewallaConfigPostMainDir   = "/home/pi/.firewalla/config/post_main.d"
	firewallaCtrldInitScriptPath = "/home/pi/.firewalla/config/post_main.d/start_ctrld.sh"
)

func setupFirewalla() error {
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return fmt.Errorf("setupFirewalla: generating dnsmasq config: %w", err)
	}
	if err := os.WriteFile(firewallaDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return fmt.Errorf("setupFirewalla: writing ctrld config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("setupFirewalla: restartDNSMasq: %w", err)
	}

	return nil
}

func cleanupFirewalla() error {
	// Removing current config.
	if err := os.Remove(firewallaDNSMasqConfigPath); err != nil {
		return fmt.Errorf("cleanupFirewalla: removing ctrld config: %w", err)
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return fmt.Errorf("cleanupFirewalla: restartDNSMasq: %w", err)
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

func postUninstallFirewalla() error {
	// Removing startup script.
	if err := os.Remove(firewallaCtrldInitScriptPath); err != nil {
		return fmt.Errorf("postUninstallFirewalla: removing startup script: %w", err)
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

func firewallaDnsmasqUpstreams() []dnsmasqUpstream {
	matches, err := filepath.Glob("/home/pi/firerouter/etc/dnsmasq.dns.*.conf")
	if err != nil {
		return nil
	}
	upstreams := make([]dnsmasqUpstream, 0, len(matches))
	for _, match := range matches {
		// Trim prefix and suffix to get the iface name only.
		ifaceName := strings.TrimSuffix(strings.TrimPrefix(match, "/home/pi/firerouter/etc/dnsmasq.dns."), ".conf")
		if netIface, _ := net.InterfaceByName(ifaceName); netIface != nil {
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
					upstreams = append(upstreams, dnsmasqUpstream{
						Ip:   netIP.IP.To4().String(),
						Port: ListenPort(),
					})
				}
			}
		}
	}
	return upstreams
}

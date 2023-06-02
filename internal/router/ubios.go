package router

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
)

var errContentFilteringEnabled = fmt.Errorf(`the "Content Filtering" feature" is enabled, which is conflicted with ctrld.\n
To disable it, folowing instruction here: %s`, toggleContentFilteringLink)

const (
	ubiosDNSMasqConfigPath     = "/run/dnsmasq.conf.d/zzzctrld.conf"
	toggleContentFilteringLink = "https://community.ui.com/questions/UDM-Pro-disable-enable-DNS-filtering/e2cc4060-e56a-4139-b200-62d7f773ff8f"
)

func setupUbiOS() error {
	// Disable dnsmasq as DNS server.
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return err
	}
	if err := os.WriteFile(ubiosDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func cleanupUbiOS() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(ubiosDNSMasqConfigPath); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallUbiOS() error {
	// See comment in postInstallEdgeOS.
	if contentFilteringEnabled() {
		return errContentFilteringEnabled
	}
	return nil
}

func ubiosRestartDNSMasq() error {
	buf, err := os.ReadFile("/run/dnsmasq.pid")
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

func contentFilteringEnabled() bool {
	st, err := os.Stat("/run/dnsfilter/dnsfilter")
	return err == nil && !st.IsDir()
}

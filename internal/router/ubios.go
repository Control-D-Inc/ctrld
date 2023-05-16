package router

import (
	"bytes"
	"os"
	"strconv"
)

const (
	ubiosDNSMasqConfigPath = "/run/dnsmasq.conf.d/zzzctrld.conf"
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
	if err := ubiosRestartDNSMasq(); err != nil {
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
	if err := ubiosRestartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallUbiOS() error {
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

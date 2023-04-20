package router

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	nvramCtrldKeyPrefix = "ctrld_"
	nvramCtrldSetupKey  = "ctrld_setup"
	nvramRCStartupKey   = "rc_startup"
)

var ddwrtJffs2NotEnabledErr = errors.New(`could not install service without jffs, follow this guide to enable:

https://wiki.dd-wrt.com/wiki/index.php/Journalling_Flash_File_System
`)

var nvramKeys = map[string]string{
	"dns_dnsmasq":     "1", // Make dnsmasq running but disable DNS ability, ctrld will replace it.
	"dnsmasq_options": "",  // Configuration of dnsmasq set by ctrld, filled by setupDDWrt.
	"dns_crypt":       "0", // Disable DNSCrypt.
}

func setupDDWrt() error {
	// Already setup.
	if val, _ := nvram("get", nvramCtrldSetupKey); val == "1" {
		return nil
	}

	data, err := dnsMasqConf()
	if err != nil {
		return err
	}
	nvramKeys["dnsmasq_options"] = data
	// Backup current value, store ctrld's configs.
	for key, value := range nvramKeys {
		old, err := nvram("get", key)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		if out, err := nvram("set", nvramCtrldKeyPrefix+key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		if out, err := nvram("set", key+"="+value); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := nvram("set", nvramCtrldSetupKey+"=1"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Commit.
	if out, err := nvram("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Restart dnsmasq service.
	if err := ddwrtRestartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func cleanupDDWrt() error {
	// Restore old configs.
	for key := range nvramKeys {
		ctrldKey := nvramCtrldKeyPrefix + key
		old, err := nvram("get", ctrldKey)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		_, _ = nvram("unset", ctrldKey)
		if out, err := nvram("set", key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := nvram("unset", "ctrld_setup"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Commit.
	if out, err := nvram("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Restart dnsmasq service.
	if err := ddwrtRestartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallDDWrt() error {
	return nil
}

func nvram(args ...string) (string, error) {
	cmd := exec.Command("nvram", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s:%w", stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func ddwrtRestartDNSMasq() error {
	if out, err := exec.Command("restart_dns").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dns: %s, %w", string(out), err)
	}
	return nil
}

func ddwrtJff2Enabled() bool {
	out, _ := nvram("get", "enable_jffs2")
	return out == "1"
}

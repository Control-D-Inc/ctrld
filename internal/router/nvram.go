package router

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

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

/*
NOTE:
  - For Openwrt, DNSSEC is not included in default dnsmasq (require dnsmasq-full).
  - For Merlin, DNSSEC is configured during postconf script (see merlinDNSMasqPostConfTmpl).
  - For Ubios UDM Pro/Dream Machine, DNSSEC is not included in their dnsmasq package:
    +https://community.ui.com/questions/Implement-DNSSEC-into-UniFi/951c72b0-4d88-4c86-9174-45417bd2f9ca
    +https://community.ui.com/questions/Enable-DNSSEC-for-Unifi-Dream-Machine-FW-updates/e68e367c-d09b-4459-9444-18908f7c1ea1
*/
func nvramKV() map[string]string {
	switch Name() {
	case DDWrt:
		return map[string]string{
			"dns_dnsmasq":     "1", // Make dnsmasq running but disable DNS ability, ctrld will replace it.
			"dnsmasq_options": "",  // Configuration of dnsmasq set by ctrld, filled by setupDDWrt.
			"dns_crypt":       "0", // Disable DNSCrypt.
			"dnssec":          "0", // Disable DNSSEC.
		}
	case Merlin:
		return map[string]string{
			"dnspriv_enable": "0", // Ensure Merlin native DoT disabled.
		}
	}
	return nil
}

func nvramSetup(m map[string]string) error {
	// Backup current value, store ctrld's configs.
	for key, value := range m {
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
	return nil
}

func nvramRestore(m map[string]string) error {
	// Restore old configs.
	for key := range m {
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
	return nil
}

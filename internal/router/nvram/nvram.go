package nvram

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	CtrldKeyPrefix  = "ctrld_"
	CtrldSetupKey   = "ctrld_setup"
	CtrldInstallKey = "ctrld_install"
	RCStartupKey    = "rc_startup"
)

// Run runs the given nvram command.
func Run(args ...string) (string, error) {
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

// SetKV writes the given key/value from map to nvram.
// The given setupKey is set to 1 to indicates key/value set.
func SetKV(m map[string]string, setupKey string) error {
	// Backup current value, store ctrld's configs.
	for key, value := range m {
		old, err := Run("get", key)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		if out, err := Run("set", CtrldKeyPrefix+key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		if out, err := Run("set", key+"="+value); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := Run("set", setupKey+"=1"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Commit.
	if out, err := Run("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	return nil
}

// Restore restores the old value of given key from map m.
// The given setupKey is set to 0 to indicates key/value restored.
func Restore(m map[string]string, setupKey string) error {
	// Restore old configs.
	for key := range m {
		ctrldKey := CtrldKeyPrefix + key
		old, err := Run("get", ctrldKey)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		_, _ = Run("unset", ctrldKey)
		if out, err := Run("set", key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := Run("unset", setupKey); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Commit.
	if out, err := Run("commit"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	return nil
}

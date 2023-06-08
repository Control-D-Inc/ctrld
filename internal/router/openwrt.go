package router

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var errUCIEntryNotFound = errors.New("uci: Entry not found")

const openwrtDNSMasqConfigPath = "/tmp/dnsmasq.d/ctrld.conf"

// IsGLiNet reports whether the router is an GL.iNet router.
func IsGLiNet() bool {
	if Name() != OpenWrt {
		return false
	}
	buf, _ := os.ReadFile("/proc/version")
	// The output of /proc/version contains "(glinet@glinet)".
	return bytes.Contains(buf, []byte(" (glinet"))
}

// IsOldOpenwrt reports whether the router is an "old" version of Openwrt,
// aka versions which don't have "service" command.
func IsOldOpenwrt() bool {
	if Name() != OpenWrt {
		return false
	}
	cmd, _ := exec.LookPath("service")
	return cmd == ""
}

func setupOpenWrt() error {
	// Delete dnsmasq port if set.
	if _, err := uci("delete", "dhcp.@dnsmasq[0].port"); err != nil && !errors.Is(err, errUCIEntryNotFound) {
		return err
	}
	dnsMasqConfigContent, err := dnsMasqConf()
	if err != nil {
		return err
	}
	if err := os.WriteFile(openwrtDNSMasqConfigPath, []byte(dnsMasqConfigContent), 0600); err != nil {
		return err
	}
	// Commit.
	if _, err := uci("commit"); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func cleanupOpenWrt() error {
	// Remove the custom dnsmasq config
	if err := os.Remove(openwrtDNSMasqConfigPath); err != nil {
		return err
	}
	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

func postInstallOpenWrt() error {
	return exec.Command("/etc/init.d/ctrld", "enable").Run()
}

func uci(args ...string) (string, error) {
	cmd := exec.Command("uci", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.HasPrefix(stderr.String(), errUCIEntryNotFound.Error()) {
			return "", errUCIEntryNotFound
		}
		return "", fmt.Errorf("%s:%w", stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func openwrtRestartDNSMasq() error {
	if out, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

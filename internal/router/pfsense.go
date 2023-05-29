package router

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kardianos/service"
)

const (
	rcPath        = "/usr/local/etc/rc.d"
	unboundRcPath = rcPath + "/unbound"
)

func setupPfsense() error {
	// If Pfsense is in DNS Resolver mode, ensure no unbound processes running.
	if _, err := exec.Command("service", "unbound", "onestatus").CombinedOutput(); err == nil {
		if out, err := exec.Command("killall", "unbound").CombinedOutput(); err != nil {
			return fmt.Errorf("could not killall unbound: %s: %w", string(out), err)
		}
	}
	// If Pfsense is in DNS Forwarder mode, ensure no dnsmasq processes running.
	if _, err := exec.Command("service", "dnsmasq", "onestatus").CombinedOutput(); err == nil {
		if out, err := exec.Command("killall", "dnsmasq").CombinedOutput(); err != nil {
			return fmt.Errorf("could not killall unbound: %s: %w", string(out), err)
		}
	}
	return nil
}

func cleanupPfsense(svc *service.Config) error {
	if err := os.Remove(filepath.Join(rcPath, svc.Name+".sh")); err != nil {
		return fmt.Errorf("os.Remove: %w", err)
	}
	if out, err := exec.Command(unboundRcPath, "onerestart").CombinedOutput(); err != nil {
		return fmt.Errorf("could not restart unbound: %s: %w", string(out), err)
	}
	if out, err := exec.Command(unboundRcPath, "onerestart").CombinedOutput(); err != nil {
		return fmt.Errorf("could not restart unbound: %s: %w", string(out), err)
	}
	return nil
}

func postInstallPfsense(svc *service.Config) error {
	// pfsense need ".sh" extension for script to be run at boot.
	// See: https://docs.netgate.com/pfsense/en/latest/development/boot-commands.html#shell-script-option
	oldname := filepath.Join(rcPath, svc.Name)
	newname := filepath.Join(rcPath, svc.Name+".sh")
	_ = os.Remove(newname)
	if err := os.Symlink(oldname, newname); err != nil {
		return fmt.Errorf("os.Symlink: %w", err)
	}
	return nil
}

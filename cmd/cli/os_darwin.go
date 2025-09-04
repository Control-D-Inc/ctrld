package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/Control-D-Inc/ctrld"
)

// allocateIP allocates an IP address on the specified interface
// sudo ifconfig lo0 alias 127.0.0.2 up
func allocateIP(ip string) error {
	mainLog.Load().Debug().Str("ip", ip).Msg("Allocating IP address")
	cmd := exec.Command("ifconfig", "lo0", "alias", ip, "up")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("AllocateIP failed")
		return err
	}
	mainLog.Load().Debug().Str("ip", ip).Msg("IP address allocated successfully")
	return nil
}

// deAllocateIP deallocates an IP address from the specified interface
func deAllocateIP(ip string) error {
	mainLog.Load().Debug().Str("ip", ip).Msg("Deallocating IP address")
	cmd := exec.Command("ifconfig", "lo0", "-alias", ip)
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("DeAllocateIP failed")
		return err
	}
	mainLog.Load().Debug().Str("ip", ip).Msg("IP address deallocated successfully")
	return nil
}

// setDnsIgnoreUnusableInterface likes setDNS, but return a nil error if the interface is not usable.
func setDnsIgnoreUnusableInterface(iface *net.Interface, nameservers []string) error {
	if err := setDNS(iface, nameservers); err != nil {
		// TODO: investiate whether we can detect this without relying on error message.
		if strings.Contains(err.Error(), " is not a recognized network service") {
			return nil
		}
		return err
	}
	return nil
}

// set the dns server for the provided network interface
// networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1
// TODO(cuonglm): use system API
func setDNS(iface *net.Interface, nameservers []string) error {
	mainLog.Load().Debug().Str("interface", iface.Name).Strs("nameservers", nameservers).Msg("Setting DNS configuration")

	// Note that networksetup won't modify search domains settings,
	// This assignment is just a placeholder to silent linter.
	_ = searchDomains
	cmd := "networksetup"
	args := []string{"-setdnsservers", iface.Name}
	args = append(args, nameservers...)
	if out, err := exec.Command(cmd, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %w", string(out), err)
	}

	mainLog.Load().Debug().Str("interface", iface.Name).Msg("DNS configuration set successfully")
	return nil
}

// resetDnsIgnoreUnusableInterface likes resetDNS, but return a nil error if the interface is not usable.
func resetDnsIgnoreUnusableInterface(iface *net.Interface) error {
	if err := resetDNS(iface); err != nil {
		// TODO: investiate whether we can detect this without relying on error message.
		if strings.Contains(err.Error(), " is not a recognized network service") {
			return nil
		}
		return err
	}
	return nil
}

// TODO(cuonglm): use system API
func resetDNS(iface *net.Interface) error {
	mainLog.Load().Debug().Str("interface", iface.Name).Msg("Resetting DNS configuration")

	cmd := "networksetup"
	args := []string{"-setdnsservers", iface.Name, "empty"}
	if out, err := exec.Command(cmd, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %w", string(out), err)
	}

	mainLog.Load().Debug().Str("interface", iface.Name).Msg("DNS configuration reset successfully")
	return nil
}

// restoreDNS restores the DNS settings of the given interface.
// this should only be executed upon turning off the ctrld service.
func restoreDNS(iface *net.Interface) (err error) {
	if ns := ctrld.SavedStaticNameservers(iface); len(ns) > 0 {
		err = setDNS(iface, ns)
	}
	return err
}

// currentDNS returns the current DNS servers for the specified interface
func currentDNS(_ *net.Interface) []string {
	return ctrld.CurrentNameserversFromResolvconf()
}

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	cmd := "networksetup"
	args := []string{"-getdnsservers", iface.Name}
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var ns []string
	for scanner.Scan() {
		line := scanner.Text()
		if ip := net.ParseIP(line); ip != nil {
			ns = append(ns, ip.String())
		}
	}
	return ns, nil
}

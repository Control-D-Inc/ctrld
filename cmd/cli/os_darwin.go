package cli

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// allocate loopback ip
// sudo ifconfig lo0 alias 127.0.0.2 up
func allocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", "alias", ip, "up")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", "-alias", ip)
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}

// set the dns server for the provided network interface
// networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1
// TODO(cuonglm): use system API
func setDNS(iface *net.Interface, nameservers []string) error {
	cmd := "networksetup"
	args := []string{"-setdnsservers", iface.Name}
	args = append(args, nameservers...)

	if err := exec.Command(cmd, args...).Run(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("setDNS failed, ips = %q", nameservers)
		return err
	}
	return nil
}

// TODO(cuonglm): use system API
func resetDNS(iface *net.Interface) error {
	if ns := savedStaticNameservers(iface); len(ns) > 0 {
		if err := setDNS(iface, ns); err == nil {
			return nil
		}
	}
	cmd := "networksetup"
	args := []string{"-setdnsservers", iface.Name, "empty"}

	if err := exec.Command(cmd, args...).Run(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("resetDNS failed")
		return err
	}
	return nil
}

func currentDNS(_ *net.Interface) []string {
	return resolvconffile.NameServers("")
}

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) []string {
	cmd := "networksetup"
	args := []string{"-getdnsservers", iface.Name}
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("could not get current static DNS")
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var ns []string
	for scanner.Scan() {
		line := scanner.Text()
		if ip := net.ParseIP(line); ip != nil {
			ns = append(ns, ip.String())
		}
	}
	return ns
}

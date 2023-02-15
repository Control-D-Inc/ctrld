package main

import (
	"errors"
	"net"
	"os/exec"
	"strconv"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

func setDNS(iface *net.Interface, nameservers []string) error {
	if len(nameservers) == 0 {
		return errors.New("empty DNS nameservers")
	}
	primaryDNS := nameservers[0]
	if err := setPrimaryDNS(iface, primaryDNS); err != nil {
		return err
	}
	if len(nameservers) > 1 {
		secondaryDNS := nameservers[1]
		_ = addSecondaryDNS(iface, secondaryDNS)
	}
	return nil
}

// TODO(cuonglm): should we use system API?
func resetDNS(iface *net.Interface) error {
	if ctrldnet.SupportsIPv6ListenLocal() {
		if output, err := netsh("interface", "ipv6", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp"); err != nil {
			mainLog.Warn().Err(err).Msgf("failed to reset ipv6 DNS: %s", string(output))
		}
	}
	output, err := netsh("interface", "ipv4", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp")
	if err != nil {
		mainLog.Error().Err(err).Msgf("failed to reset ipv4 DNS: %s", string(output))
		return err
	}
	return nil
}

func setPrimaryDNS(iface *net.Interface, dns string) error {
	ipVer := "ipv4"
	if ctrldnet.IsIPv6(dns) {
		ipVer = "ipv6"
	}
	idx := strconv.Itoa(iface.Index)
	output, err := netsh("interface", ipVer, "set", "dnsserver", idx, "static", dns)
	if err != nil {
		mainLog.Error().Err(err).Msgf("failed to set primary DNS: %s", string(output))
		return err
	}
	if ipVer == "ipv4" {
		// Disable IPv6 DNS, so the query will be fallback to IPv4.
		_, _ = netsh("interface", "ipv6", "set", "dnsserver", idx, "static", "::1", "primary")
	}

	return nil
}

func addSecondaryDNS(iface *net.Interface, dns string) error {
	ipVer := "ipv4"
	if ctrldnet.IsIPv6(dns) {
		ipVer = "ipv6"
	}
	output, err := netsh("interface", ipVer, "add", "dns", strconv.Itoa(iface.Index), dns, "index=2")
	if err != nil {
		mainLog.Warn().Err(err).Msgf("failed to add secondary DNS: %s", string(output))
	}
	return nil
}

func netsh(args ...string) ([]byte, error) {
	return exec.Command("netsh", args...).Output()
}

func currentDNS(iface *net.Interface) []string {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		mainLog.Error().Err(err).Msg("failed to get interface LUID")
		return nil
	}
	nameservers, err := luid.DNS()
	if err != nil {
		mainLog.Error().Err(err).Msg("failed to get interface DNS")
		return nil
	}
	ns := make([]string, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, nameserver.String())
	}
	return ns
}

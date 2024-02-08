package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

const forwardersFilename = ".forwarders.txt"

var (
	setDNSOnce   sync.Once
	resetDNSOnce sync.Once
)

func setDNS(iface *net.Interface, nameservers []string) error {
	if len(nameservers) == 0 {
		return errors.New("empty DNS nameservers")
	}
	setDNSOnce.Do(func() {
		// If there's a Dns server running, that means we are on AD with Dns feature enabled.
		// Configuring the Dns server to forward queries to ctrld instead.
		if windowsHasLocalDnsServerRunning() {
			file := absHomeDir(forwardersFilename)
			if data, _ := os.ReadFile(file); len(data) > 0 {
				if err := removeDnsServerForwarders(strings.Split(string(data), ",")); err != nil {
					mainLog.Load().Error().Err(err).Msg("could not remove current forwarders settings")
				} else {
					mainLog.Load().Debug().Msg("removed current forwarders settings.")
				}
			}
			if err := os.WriteFile(file, []byte(strings.Join(nameservers, ",")), 0600); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not save forwarders settings")
			}
			if err := addDnsServerForwarders(nameservers); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not set forwarders settings")
			}
		}
	})
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
	resetDNSOnce.Do(func() {
		// See corresponding comment in setDNS.
		if windowsHasLocalDnsServerRunning() {
			file := absHomeDir(forwardersFilename)
			content, err := os.ReadFile(file)
			if err != nil {
				mainLog.Load().Error().Err(err).Msg("could not read forwarders settings")
				return
			}
			nameservers := strings.Split(string(content), ",")
			if err := removeDnsServerForwarders(nameservers); err != nil {
				mainLog.Load().Error().Err(err).Msg("could not remove forwarders settings")
				return
			}
		}
	})

	if ns := savedNameservers(iface); len(ns) > 0 {
		if err := setDNS(iface, ns); err == nil {
			return nil
		}
	}
	if ctrldnet.SupportsIPv6ListenLocal() {
		if output, err := netsh("interface", "ipv6", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp"); err != nil {
			mainLog.Load().Warn().Err(err).Msgf("failed to reset ipv6 DNS: %s", string(output))
		}
	}
	output, err := netsh("interface", "ipv4", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp")
	if err != nil {
		mainLog.Load().Error().Err(err).Msgf("failed to reset ipv4 DNS: %s", string(output))
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
		mainLog.Load().Error().Err(err).Msgf("failed to set primary DNS: %s", string(output))
		return err
	}
	if ipVer == "ipv4" && ctrldnet.SupportsIPv6ListenLocal() {
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
		mainLog.Load().Warn().Err(err).Msgf("failed to add secondary DNS: %s", string(output))
	}
	return nil
}

func netsh(args ...string) ([]byte, error) {
	return exec.Command("netsh", args...).Output()
}

func currentDNS(iface *net.Interface) []string {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to get interface LUID")
		return nil
	}
	nameservers, err := luid.DNS()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to get interface DNS")
		return nil
	}
	ns := make([]string, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, nameserver.String())
	}
	return ns
}

// addDnsServerForwarders adds given nameservers to DNS server forwarders list.
func addDnsServerForwarders(nameservers []string) error {
	for _, ns := range nameservers {
		cmd := fmt.Sprintf("Add-DnsServerForwarder -IPAddress %s", ns)
		if out, err := powershell(cmd); err != nil {
			return fmt.Errorf("%w: %s", err, string(out))
		}
	}
	return nil
}

// removeDnsServerForwarders removes given nameservers from DNS server forwarders list.
func removeDnsServerForwarders(nameservers []string) error {
	for _, ns := range nameservers {
		cmd := fmt.Sprintf("Remove-DnsServerForwarder -IPAddress %s -Force", ns)
		if out, err := powershell(cmd); err != nil {
			return fmt.Errorf("%w: %s", err, string(out))
		}
	}
	return nil
}

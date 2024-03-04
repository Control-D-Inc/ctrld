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

const (
	forwardersFilename       = ".forwarders.txt"
	v4InterfaceKeyPathFormat = `HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	v6InterfaceKeyPathFormat = `HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
)

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
	if err := setPrimaryDNS(iface, primaryDNS, true); err != nil {
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

	// Restoring ipv6 first.
	if ctrldnet.SupportsIPv6ListenLocal() {
		if output, err := netsh("interface", "ipv6", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp"); err != nil {
			mainLog.Load().Warn().Err(err).Msgf("failed to reset ipv6 DNS: %s", string(output))
		}
	}
	// Restoring ipv4 DHCP.
	output, err := netsh("interface", "ipv4", "set", "dnsserver", strconv.Itoa(iface.Index), "dhcp")
	if err != nil {
		return fmt.Errorf("%s: %w", string(output), err)
	}
	// If there's static DNS saved, restoring it.
	if nss := savedStaticNameservers(iface); len(nss) > 0 {
		v4ns := make([]string, 0, 2)
		v6ns := make([]string, 0, 2)
		for _, ns := range nss {
			if ctrldnet.IsIPv6(ns) {
				v6ns = append(v6ns, ns)
			} else {
				v4ns = append(v4ns, ns)
			}
		}

		for _, ns := range [][]string{v4ns, v6ns} {
			if len(ns) == 0 {
				continue
			}
			primaryDNS := ns[0]
			if err := setPrimaryDNS(iface, primaryDNS, false); err != nil {
				return err
			}
			if len(ns) > 1 {
				secondaryDNS := ns[1]
				_ = addSecondaryDNS(iface, secondaryDNS)
			}
		}
	}
	return nil
}

func setPrimaryDNS(iface *net.Interface, dns string, disablev6 bool) error {
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
	if disablev6 && ipVer == "ipv4" && ctrldnet.SupportsIPv6ListenLocal() {
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

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return nil, err
	}
	guid, err := luid.GUID()
	if err != nil {
		return nil, err
	}
	var ns []string
	for _, path := range []string{v4InterfaceKeyPathFormat, v6InterfaceKeyPathFormat} {
		interfaceKeyPath := path + guid.String()
		found := false
		for _, key := range []string{"NameServer", "ProfileNameServer"} {
			if found {
				continue
			}
			cmd := fmt.Sprintf(`Get-ItemPropertyValue -Path "%s" -Name "%s"`, interfaceKeyPath, key)
			out, err := powershell(cmd)
			if err == nil && len(out) > 0 {
				found = true
				ns = append(ns, strings.Split(string(out), ",")...)
			}
		}
	}
	return ns, nil
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

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/Control-D-Inc/ctrld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

const (
	v4InterfaceKeyPathFormat = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	v6InterfaceKeyPathFormat = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
)

var (
	setDNSOnce   sync.Once
	resetDNSOnce sync.Once
)

// setDnsIgnoreUnusableInterface likes setDNS, but return a nil error if the interface is not usable.
func setDnsIgnoreUnusableInterface(iface *net.Interface, nameservers []string) error {
	return setDNS(iface, nameservers)
}

// setDNS sets the dns server for the provided network interface
func setDNS(iface *net.Interface, nameservers []string) error {
	if len(nameservers) == 0 {
		return errors.New("empty DNS nameservers")
	}
	setDNSOnce.Do(func() {
		// If there's a Dns server running, that means we are on AD with Dns feature enabled.
		// Configuring the Dns server to forward queries to ctrld instead.
		if hasLocalDnsServerRunning() {
			mainLog.Load().Debug().Msg("Local DNS server detected, configuring forwarders")

			file := absHomeDir(windowsForwardersFilename)
			mainLog.Load().Debug().Msgf("Using forwarders file: %s", file)

			oldForwardersContent, err := os.ReadFile(file)
			if err != nil {
				mainLog.Load().Debug().Err(err).Msg("Could not read existing forwarders file")
			} else {
				mainLog.Load().Debug().Msgf("Existing forwarders content: %s", string(oldForwardersContent))
			}

			hasLocalIPv6Listener := needLocalIPv6Listener()
			mainLog.Load().Debug().Bool("has_ipv6_listener", hasLocalIPv6Listener).Msg("IPv6 listener status")

			forwarders := slices.DeleteFunc(slices.Clone(nameservers), func(s string) bool {
				if !hasLocalIPv6Listener {
					return false
				}
				return s == "::1"
			})
			mainLog.Load().Debug().Strs("forwarders", forwarders).Msg("Filtered forwarders list")

			if err := os.WriteFile(file, []byte(strings.Join(forwarders, ",")), 0600); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not save forwarders settings")
			} else {
				mainLog.Load().Debug().Msg("Successfully wrote new forwarders file")
			}

			oldForwarders := strings.Split(string(oldForwardersContent), ",")
			mainLog.Load().Debug().Strs("old_forwarders", oldForwarders).Msg("Previous forwarders")

			if err := addDnsServerForwarders(forwarders, oldForwarders); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not set forwarders settings")
			} else {
				mainLog.Load().Debug().Msg("Successfully configured DNS server forwarders")
			}
		}
	})
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("setDNS: %w", err)
	}
	var (
		serversV4 []netip.Addr
		serversV6 []netip.Addr
	)
	for _, ns := range nameservers {
		if addr, err := netip.ParseAddr(ns); err == nil {
			if addr.Is4() {
				serversV4 = append(serversV4, addr)
			} else {
				serversV6 = append(serversV6, addr)
			}
		}
	}

	// Note that Windows won't modify the current search domains if passing nil to luid.SetDNS function.
	// searchDomains is still implemented for Windows just in case Windows API changes in future versions.
	_ = searchDomains

	if len(serversV4) == 0 && len(serversV6) == 0 {
		return errors.New("invalid DNS nameservers")
	}
	if len(serversV4) > 0 {
		if err := luid.SetDNS(windows.AF_INET, serversV4, nil); err != nil {
			return fmt.Errorf("could not set DNS ipv4: %w", err)
		}
	}
	if len(serversV6) > 0 {
		if err := luid.SetDNS(windows.AF_INET6, serversV6, nil); err != nil {
			return fmt.Errorf("could not set DNS ipv6: %w", err)
		}
	}
	return nil
}

// resetDnsIgnoreUnusableInterface likes resetDNS, but return a nil error if the interface is not usable.
func resetDnsIgnoreUnusableInterface(iface *net.Interface) error {
	return resetDNS(iface)
}

// TODO(cuonglm): should we use system API?
func resetDNS(iface *net.Interface) error {
	resetDNSOnce.Do(func() {
		// See corresponding comment in setDNS.
		if hasLocalDnsServerRunning() {
			file := absHomeDir(windowsForwardersFilename)
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

	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("resetDNS: %w", err)
	}
	// Restoring DHCP settings.
	if err := luid.SetDNS(windows.AF_INET, nil, nil); err != nil {
		return fmt.Errorf("could not reset DNS ipv4: %w", err)
	}
	if err := luid.SetDNS(windows.AF_INET6, nil, nil); err != nil {
		return fmt.Errorf("could not reset DNS ipv6: %w", err)
	}
	return nil
}

// restoreDNS restores the DNS settings of the given interface.
// this should only be executed upon turning off the ctrld service.
func restoreDNS(iface *net.Interface) (err error) {
	if nss := ctrld.SavedStaticNameservers(iface); len(nss) > 0 {
		v4ns := make([]string, 0, 2)
		v6ns := make([]string, 0, 2)
		for _, ns := range nss {
			if ctrldnet.IsIPv6(ns) {
				v6ns = append(v6ns, ns)
			} else {
				v4ns = append(v4ns, ns)
			}
		}

		luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return fmt.Errorf("restoreDNS: %w", err)
		}

		if len(v4ns) > 0 {
			mainLog.Load().Debug().Msgf("restoring IPv4 static DNS for interface %q: %v", iface.Name, v4ns)
			if err := setDNS(iface, v4ns); err != nil {
				return fmt.Errorf("restoreDNS (IPv4): %w", err)
			}
		} else {
			mainLog.Load().Debug().Msgf("restoring IPv4 DHCP for interface %q", iface.Name)
			if err := luid.SetDNS(windows.AF_INET, nil, nil); err != nil {
				return fmt.Errorf("restoreDNS (IPv4 clear): %w", err)
			}
		}

		if len(v6ns) > 0 {
			mainLog.Load().Debug().Msgf("restoring IPv6 static DNS for interface %q: %v", iface.Name, v6ns)
			if err := setDNS(iface, v6ns); err != nil {
				return fmt.Errorf("restoreDNS (IPv6): %w", err)
			}
		} else {
			mainLog.Load().Debug().Msgf("restoring IPv6 DHCP for interface %q", iface.Name)
			if err := luid.SetDNS(windows.AF_INET6, nil, nil); err != nil {
				return fmt.Errorf("restoreDNS (IPv6 clear): %w", err)
			}
		}
	}
	return err
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

// currentStaticDNS checks both the IPv4 and IPv6 paths for static DNS values using keys
// like "NameServer" and "ProfileNameServer".
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return nil, fmt.Errorf("fallback winipcfg.LUIDFromIndex: %w", err)
	}
	guid, err := luid.GUID()
	if err != nil {
		return nil, fmt.Errorf("fallback luid.GUID: %w", err)
	}

	var ns []string
	keyPaths := []string{v4InterfaceKeyPathFormat, v6InterfaceKeyPathFormat}
	for _, path := range keyPaths {
		interfaceKeyPath := path + guid.String()
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, interfaceKeyPath, registry.QUERY_VALUE)
		if err != nil {
			mainLog.Load().Debug().Err(err).Msgf("failed to open registry key %q for interface %q; trying next key", interfaceKeyPath, iface.Name)
			continue
		}
		func() {
			defer k.Close()
			for _, keyName := range []string{"NameServer", "ProfileNameServer"} {
				value, _, err := k.GetStringValue(keyName)
				if err != nil && !errors.Is(err, registry.ErrNotExist) {
					mainLog.Load().Debug().Err(err).Msgf("error reading %s registry key", keyName)
					continue
				}
				if len(value) > 0 {
					mainLog.Load().Debug().Msgf("found static DNS for interface %q: %s", iface.Name, value)
					parsed := parseDNSServers(value)
					for _, pns := range parsed {
						if !slices.Contains(ns, pns) {
							ns = append(ns, pns)
						}
					}
				}
			}
		}()
	}
	if len(ns) == 0 {
		mainLog.Load().Debug().Msgf("no static DNS values found for interface %q", iface.Name)
	}
	return ns, nil
}

// parseDNSServers splits a DNS server string that may be comma- or space-separated,
// and trims any extraneous whitespace or null characters.
func parseDNSServers(val string) []string {
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ' ' || r == ','
	})
	var servers []string
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if len(trimmed) > 0 {
			servers = append(servers, trimmed)
		}
	}
	return servers
}

// addDnsServerForwarders adds given nameservers to DNS server forwarders list,
// and also removing old forwarders if provided.
func addDnsServerForwarders(nameservers, old []string) error {
	newForwardersMap := make(map[string]struct{})
	newForwarders := make([]string, len(nameservers))
	for i := range nameservers {
		newForwardersMap[nameservers[i]] = struct{}{}
		newForwarders[i] = fmt.Sprintf("%q", nameservers[i])
	}
	oldForwarders := old[:0]
	for _, fwd := range old {
		if _, ok := newForwardersMap[fwd]; !ok {
			oldForwarders = append(oldForwarders, fwd)
		}
	}
	// NOTE: It is important to add new forwarder before removing old one.
	//       Testing on Windows Server 2022 shows that removing forwarder1
	//       then adding forwarder2 sometimes ends up adding both of them
	//       to the forwarders list.
	cmd := fmt.Sprintf("Add-DnsServerForwarder -IPAddress %s", strings.Join(newForwarders, ","))
	if len(oldForwarders) > 0 {
		cmd = fmt.Sprintf("%s ; Remove-DnsServerForwarder -IPAddress %s -Force", cmd, strings.Join(oldForwarders, ","))
	}
	if out, err := powershell(cmd); err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
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

// powershell runs the given powershell command.
func powershell(cmd string) ([]byte, error) {
	out, err := exec.Command("powershell", "-Command", cmd).CombinedOutput()
	return bytes.TrimSpace(out), err
}

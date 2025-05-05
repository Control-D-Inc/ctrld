//go:build darwin

package ctrld

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"tailscale.com/net/netmon"
)

func dnsFns() []dnsFn {
	return []dnsFn{dnsFromResolvConf, getDNSFromScutil, getAllDHCPNameservers}
}

func getDNSFromScutil() []string {
	logger := *ProxyLogger.Load()

	const (
		maxRetries    = 10
		retryInterval = 100 * time.Millisecond
	)

	regularIPs, loopbackIPs, _ := netmon.LocalAddresses()

	var nameservers []string
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryInterval)
		}

		cmd := exec.Command("scutil", "--dns")
		output, err := cmd.Output()
		if err != nil {
			Log(context.Background(), logger.Error(), "failed to execute scutil --dns (attempt %d/%d): %v", attempt+1, maxRetries, err)
			continue
		}

		var localDNS []string
		seen := make(map[string]bool)

		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "nameserver[") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					ns := strings.TrimSpace(parts[1])
					if ip := net.ParseIP(ns); ip != nil {
						// skip loopback IPs
						isLocal := false
						for _, v := range slices.Concat(regularIPs, loopbackIPs) {
							ipStr := v.String()
							if ip.String() == ipStr {
								isLocal = true
								break
							}
						}
						if !isLocal && !seen[ip.String()] {
							seen[ip.String()] = true
							localDNS = append(localDNS, ip.String())
						}
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			Log(context.Background(), logger.Error(), "error scanning scutil output (attempt %d/%d): %v", attempt+1, maxRetries, err)
			continue
		}

		// If we successfully read the output and found nameservers, return them
		if len(localDNS) > 0 {
			return localDNS
		}
	}

	return nameservers
}

func getDHCPNameservers(iface string) ([]string, error) {
	// Run the ipconfig command for the given interface.
	cmd := exec.Command("ipconfig", "getpacket", iface)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running ipconfig: %v", err)
	}

	// Look for a line like:
	//     domain_name_servers = 192.168.1.1 8.8.8.8;
	re := regexp.MustCompile(`domain_name_servers\s*=\s*(.*);`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return nil, fmt.Errorf("no DHCP nameservers found")
	}

	// Split the nameservers by whitespace.
	nameservers := strings.Fields(matches[1])
	return nameservers, nil
}

func getAllDHCPNameservers() []string {
	logger := *ProxyLogger.Load()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	regularIPs, loopbackIPs, _ := netmon.LocalAddresses()

	var allNameservers []string
	seen := make(map[string]bool)

	for _, iface := range interfaces {
		// Skip interfaces that are:
		// - down
		// - loopback
		// - not physical (virtual)
		// - point-to-point (like VPN interfaces)
		// - without MAC address (non-physical)
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagPointToPoint != 0 ||
			(iface.Flags&net.FlagBroadcast == 0 &&
				iface.Flags&net.FlagMulticast == 0) ||
			len(iface.HardwareAddr) == 0 ||
			strings.HasPrefix(iface.Name, "utun") ||
			strings.HasPrefix(iface.Name, "llw") ||
			strings.HasPrefix(iface.Name, "awdl") {
			continue
		}

		// Verify it's a valid MAC address (should be 6 bytes for IEEE 802 MAC-48)
		if len(iface.HardwareAddr) != 6 {
			continue
		}

		nameservers, err := getDHCPNameservers(iface.Name)
		if err != nil {
			continue
		}

		// Add unique nameservers to the result, skipping local IPs
		for _, ns := range nameservers {
			if ip := net.ParseIP(ns); ip != nil {
				// skip loopback and local IPs
				isLocal := false
				for _, v := range slices.Concat(regularIPs, loopbackIPs) {
					if ip.String() == v.String() {
						isLocal = true
						break
					}
				}
				if !isLocal && !seen[ns] {
					seen[ns] = true
					allNameservers = append(allNameservers, ns)
				}
			}
		}
	}

	// if we have static DNS servers saved for the current default route, we should add them to the list
	drIfaceName, err := netmon.DefaultRouteInterface()
	Log(context.Background(), logger.Debug(), "checking for static DNS servers for default route interface: %s", drIfaceName)
	if err != nil {
		Log(context.Background(), logger.Debug(),
			"Failed to get default route interface: %v", err)
	} else {
		drIface, err := net.InterfaceByName(drIfaceName)
		if err != nil {
			Log(context.Background(), logger.Debug(),
				"Failed to get interface by name %s: %v", drIfaceName, err)
		} else if drIface != nil {
			if _, err := patchNetIfaceName(drIface); err != nil {
				Log(context.Background(), logger.Debug(),
					"Failed to patch interface name %s: %v", drIfaceName, err)
			}
			staticNs, file := SavedStaticNameserversAndPath(drIface)
			Log(context.Background(), logger.Debug(),
				"static dns servers from %s: %v", file, staticNs)
			if len(staticNs) > 0 {
				Log(context.Background(), logger.Debug(),
					"Adding static DNS servers from %s: %v", drIface.Name, staticNs)
				allNameservers = append(allNameservers, staticNs...)
			}
		}
	}

	return allNameservers
}

func patchNetIfaceName(iface *net.Interface) (bool, error) {
	b, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return false, err
	}

	patched := false
	if name := networkServiceName(iface.Name, bytes.NewReader(b)); name != "" {
		patched = true
		iface.Name = name
	}
	return patched, nil
}

func networkServiceName(ifaceName string, r io.Reader) string {
	scanner := bufio.NewScanner(r)
	prevLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "*") {
			// Network services is disabled.
			continue
		}
		if !strings.Contains(line, "Device: "+ifaceName) {
			prevLine = line
			continue
		}
		parts := strings.SplitN(prevLine, " ", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

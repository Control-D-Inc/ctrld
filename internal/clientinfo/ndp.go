package clientinfo

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
)

// ndpDiscover provides client discovery functionality using NDP protocol.
type ndpDiscover struct {
	mac sync.Map // ip  => mac
	ip  sync.Map // mac => ip
}

// refresh re-scans the NDP table.
func (nd *ndpDiscover) refresh() error {
	nd.scan()
	return nil
}

// LookupIP returns the ipv6 associated with the input MAC address.
func (nd *ndpDiscover) LookupIP(mac string) string {
	val, ok := nd.ip.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

// LookupMac returns the MAC address of the given IP address.
func (nd *ndpDiscover) LookupMac(ip string) string {
	val, ok := nd.mac.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

// String returns human-readable format of ndpDiscover.
func (nd *ndpDiscover) String() string {
	return "ndp"
}

// List returns all known IP addresses.
func (nd *ndpDiscover) List() []string {
	if nd == nil {
		return nil
	}
	var ips []string
	nd.ip.Range(func(key, value any) bool {
		ips = append(ips, value.(string))
		return true
	})
	nd.mac.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

// scanWindows populates NDP table using information from "netsh" command.
func (nd *ndpDiscover) scanWindows(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if mac := parseMAC(fields[1]); mac != "" {
			nd.mac.Store(fields[0], mac)
			nd.ip.Store(mac, fields[0])
		}
	}
}

// scanUnix populates NDP table using information from "ndp" command.
func (nd *ndpDiscover) scanUnix(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if mac := parseMAC(fields[1]); mac != "" {
			ip := fields[0]
			if idx := strings.IndexByte(ip, '%'); idx != -1 {
				ip = ip[:idx]
			}
			nd.mac.Store(ip, mac)
			nd.ip.Store(mac, ip)
		}
	}
}

// normalizeMac ensure the given MAC address have the proper format
// before being parsed.
//
// Example, changing "00:0:00:0:00:01" to "00:00:00:00:00:01", which
// can be seen on Darwin.
func normalizeMac(mac string) string {
	if len(mac) == 17 {
		return mac
	}
	// Windows use "-" instead of ":" as separator.
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, c := range parts {
		if len(c) == 1 {
			parts[i] = "0" + c
		}
	}
	return strings.Join(parts, ":")
}

// parseMAC parses the input MAC, doing normalization,
// and return the result after calling net.ParseMac function.
func parseMAC(mac string) string {
	hw, _ := net.ParseMAC(normalizeMac(mac))
	return hw.String()
}

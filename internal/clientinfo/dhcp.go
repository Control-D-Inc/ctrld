package clientinfo

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"tailscale.com/net/netmon"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/util/lineread"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

type dhcp struct {
	mac2name sync.Map // mac => name
	ip2name  sync.Map // ip  => name
	ip       sync.Map // mac => ip
	mac      sync.Map // ip  => mac

	watcher *fsnotify.Watcher
	selfIP  string
}

func (d *dhcp) init() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	d.addSelf()
	d.watcher = watcher
	for file, format := range clientInfoFiles {
		// Ignore errors for default lease files.
		_ = d.addLeaseFile(file, format)
	}
	return nil
}

func (d *dhcp) watchChanges() {
	if d.watcher == nil {
		return
	}
	if dir := router.LeaseFilesDir(); dir != "" {
		if err := d.watcher.Add(dir); err != nil {
			ctrld.ProxyLogger.Load().Err(err).Str("dir", dir).Msg("could not watch lease dir")
		}
	}
	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) {
				if format, ok := clientInfoFiles[event.Name]; ok {
					if err := d.addLeaseFile(event.Name, format); err != nil {
						ctrld.ProxyLogger.Load().Err(err).Str("file", event.Name).Msg("could not add lease file")
					}
				}
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Chmod) || event.Has(fsnotify.Remove) {
				format := clientInfoFiles[event.Name]
				if err := d.readLeaseFile(event.Name, format); err != nil && !os.IsNotExist(err) {
					ctrld.ProxyLogger.Load().Err(err).Str("file", event.Name).Msg("leases file changed but failed to update client info")
				}
			}
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			ctrld.ProxyLogger.Load().Err(err).Msg("could not watch client info file")
		}
	}

}

func (d *dhcp) LookupIP(mac string) string {
	val, ok := d.ip.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

func (d *dhcp) LookupMac(ip string) string {
	val, ok := d.mac.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

func (d *dhcp) LookupHostnameByIP(ip string) string {
	val, ok := d.ip2name.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

func (d *dhcp) LookupHostnameByMac(mac string) string {
	val, ok := d.mac2name.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

func (d *dhcp) String() string {
	return "dhcp"
}

func (d *dhcp) List() []string {
	if d == nil {
		return nil
	}
	var ips []string
	d.ip.Range(func(key, value any) bool {
		ips = append(ips, value.(string))
		return true
	})
	d.mac.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

func (d *dhcp) lookupIPByHostname(name string, v6 bool) string {
	if d == nil {
		return ""
	}
	var (
		rfc1918Addrs []netip.Addr
		others       []netip.Addr
	)
	d.ip2name.Range(func(key, value any) bool {
		if value != name {
			return true
		}
		if addr, err := netip.ParseAddr(key.(string)); err == nil && addr.Is6() == v6 {
			if addr.IsPrivate() {
				rfc1918Addrs = append(rfc1918Addrs, addr)
			} else {
				others = append(others, addr)
			}
		}
		return true
	})
	result := [][]netip.Addr{rfc1918Addrs, others}
	for _, addrs := range result {
		if len(addrs) > 0 {
			sort.Slice(addrs, func(i, j int) bool {
				return addrs[i].Less(addrs[j])
			})
			return addrs[0].String()
		}
	}
	return ""
}

// AddLeaseFile adds given lease file for reading/watching clients info.
func (d *dhcp) addLeaseFile(name string, format ctrld.LeaseFileFormat) error {
	if d.watcher == nil {
		return nil
	}
	if err := d.readLeaseFile(name, format); err != nil {
		return fmt.Errorf("could not read lease file: %w", err)
	}
	clientInfoFiles[name] = format
	return d.watcher.Add(name)
}

// readLeaseFile reads the lease file with given format, saving client information to dhcp table.
func (d *dhcp) readLeaseFile(name string, format ctrld.LeaseFileFormat) error {
	switch format {
	case ctrld.Dnsmasq:
		return d.dnsmasqReadClientInfoFile(name)
	case ctrld.IscDhcpd:
		return d.iscDHCPReadClientInfoFile(name)
	case ctrld.KeaDHCP4:
		return d.keaDhcp4ReadClientInfoFile(name)
	}
	return fmt.Errorf("unsupported format: %s, file: %s", format, name)
}

// dnsmasqReadClientInfoFile populates dhcp table with client info reading from dnsmasq lease file.
func (d *dhcp) dnsmasqReadClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return d.dnsmasqReadClientInfoReader(f)

}

// dnsmasqReadClientInfoReader performs the same task as dnsmasqReadClientInfoFile,
// but by reading from an io.Reader instead of file.
func (d *dhcp) dnsmasqReadClientInfoReader(reader io.Reader) error {
	return lineread.Reader(reader, func(line []byte) error {
		fields := bytes.Fields(line)
		if len(fields) < 4 {
			return nil
		}

		mac := string(fields[1])
		if _, err := net.ParseMAC(mac); err != nil {
			// The second field is not a dhcp, skip.
			return nil
		}
		ip := normalizeIP(string(fields[2]))
		if net.ParseIP(ip) == nil {
			ctrld.ProxyLogger.Load().Warn().Msgf("invalid ip address entry: %q", ip)
			ip = ""
		}

		d.mac.Store(ip, mac)
		d.ip.Store(mac, ip)
		hostname := string(fields[3])
		if hostname == "*" {
			return nil
		}
		name := normalizeHostname(hostname)
		d.mac2name.Store(mac, name)
		d.ip2name.Store(ip, name)
		return nil
	})
}

// iscDHCPReadClientInfoFile populates dhcp table with client info reading from isc-dhcpd lease file.
func (d *dhcp) iscDHCPReadClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return d.iscDHCPReadClientInfoReader(f)
}

// iscDHCPReadClientInfoReader performs the same task as iscDHCPReadClientInfoFile,
// but by reading from an io.Reader instead of file.
func (d *dhcp) iscDHCPReadClientInfoReader(reader io.Reader) error {
	s := bufio.NewScanner(reader)
	var ip, mac, hostname string
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "}") {
			d.mac.Store(ip, mac)
			d.ip.Store(mac, ip)
			if hostname != "" && hostname != "*" {
				name := normalizeHostname(hostname)
				d.mac2name.Store(mac, name)
				d.ip2name.Store(ip, hostname)
				ip, mac, hostname = "", "", ""
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "lease":
			ip = normalizeIP(strings.ToLower(fields[1]))
			if net.ParseIP(ip) == nil {
				ctrld.ProxyLogger.Load().Warn().Msgf("invalid ip address entry: %q", ip)
				ip = ""
			}
		case "hardware":
			if len(fields) >= 3 {
				mac = strings.ToLower(strings.TrimRight(fields[2], ";"))
				if _, err := net.ParseMAC(mac); err != nil {
					// Invalid dhcp, skip.
					mac = ""
				}
			}
		case "client-hostname":
			hostname = strings.Trim(fields[1], `";`)
		}
	}
	return nil
}

// keaDhcp4ReadClientInfoFile populates dhcp table with client info reading from kea dhcp4 lease file.
func (d *dhcp) keaDhcp4ReadClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return d.keaDhcp4ReadClientInfoReader(bufio.NewReader(f))

}

// keaDhcp4ReadClientInfoReader performs the same task as keaDhcp4ReadClientInfoFile,
// but by reading from an io.Reader instead of file.
func (d *dhcp) keaDhcp4ReadClientInfoReader(r io.Reader) error {
	cr := csv.NewReader(r)
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(record) < 9 {
			continue // hostname is at 9th field, so skipping record with not enough fields.
		}
		if record[0] == "address" {
			continue // skip header.
		}
		mac := record[1]
		if _, err := net.ParseMAC(mac); err != nil { // skip invalid MAC
			continue
		}
		ip := normalizeIP(record[0])
		if net.ParseIP(ip) == nil {
			ctrld.ProxyLogger.Load().Warn().Msgf("invalid ip address entry: %q", ip)
			ip = ""
		}

		d.mac.Store(ip, mac)
		d.ip.Store(mac, ip)
		hostname := record[8]
		if hostname == "*" {
			continue
		}
		name := normalizeHostname(hostname)
		d.mac2name.Store(mac, name)
		d.ip2name.Store(ip, name)
	}
	return nil
}

// addSelf populates current host info to dhcp, so queries from
// the host itself can be attached with proper client info.
func (d *dhcp) addSelf() {
	hostname, err := os.Hostname()
	if err != nil {
		ctrld.ProxyLogger.Load().Err(err).Msg("could not get hostname")
		return
	}
	hostname = normalizeHostname(hostname)
	d.ip2name.Store(ipV4Loopback, hostname)
	d.ip2name.Store(ipv6Loopback, hostname)
	found := false
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		mac := i.HardwareAddr.String()
		// Skip loopback interfaces, info was stored above.
		if mac == "" {
			return
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if found {
				return
			}
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			d.mac.Store(ip.String(), mac)
			d.ip.Store(mac, ip.String())
			if ip.To4() != nil {
				d.mac.Store(ipV4Loopback, mac)
			} else {
				d.mac.Store(ipv6Loopback, mac)
			}
			d.mac2name.Store(mac, hostname)
			d.ip2name.Store(ip.String(), hostname)
			// If we have self IP set, and this IP is it, use this IP only.
			if ip.String() == d.selfIP {
				found = true
				d.mac.Store(ipV4Loopback, mac)
				d.mac.Store(ipv6Loopback, mac)
			}
		}
	})
	for _, netIface := range router.SelfInterfaces() {
		mac := netIface.HardwareAddr.String()
		if mac == "" {
			return
		}
		d.mac2name.Store(mac, hostname)
		addrs, _ := netIface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			d.mac.LoadOrStore(ip.String(), mac)
			d.ip.LoadOrStore(mac, ip.String())
			d.ip2name.Store(ip.String(), hostname)
		}
	}
}

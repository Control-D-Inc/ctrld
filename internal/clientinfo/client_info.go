package clientinfo

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/util/lineread"

	"github.com/Control-D-Inc/ctrld"
)

// clientInfoFiles specifies client info files and how to read them on supported platforms.
var clientInfoFiles = map[string]ctrld.LeaseFileFormat{
	"/tmp/dnsmasq.leases":                      ctrld.Dnsmasq,  // ddwrt
	"/tmp/dhcp.leases":                         ctrld.Dnsmasq,  // openwrt
	"/var/lib/misc/dnsmasq.leases":             ctrld.Dnsmasq,  // merlin
	"/mnt/data/udapi-config/dnsmasq.lease":     ctrld.Dnsmasq,  // UDM Pro
	"/data/udapi-config/dnsmasq.lease":         ctrld.Dnsmasq,  // UDR
	"/etc/dhcpd/dhcpd-leases.log":              ctrld.Dnsmasq,  // Synology
	"/tmp/var/lib/misc/dnsmasq.leases":         ctrld.Dnsmasq,  // Tomato
	"/run/dnsmasq-dhcp.leases":                 ctrld.Dnsmasq,  // EdgeOS
	"/run/dhcpd.leases":                        ctrld.IscDhcpd, // EdgeOS
	"/var/dhcpd/var/db/dhcpd.leases":           ctrld.IscDhcpd, // Pfsense
	"/home/pi/.router/run/dhcp/dnsmasq.leases": ctrld.Dnsmasq,  // Firewalla
}

// NewMacTable returns new Mac table to record client information.
func NewMacTable() *MacTable {
	return &MacTable{}
}

// MacTable records clients information by MAC address.
type MacTable struct {
	mac     sync.Map
	watcher *fsnotify.Watcher
}

// Init initializes recording client info.
func (mt *MacTable) Init() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	mt.watcher = watcher
	for file, format := range clientInfoFiles {
		// Ignore errors for default lease files.
		_ = mt.AddLeaseFile(file, format)
	}
	return nil
}

// AddLeaseFile adds given lease file for reading/watching clients info.
func (mt *MacTable) AddLeaseFile(name string, format ctrld.LeaseFileFormat) error {
	if err := mt.readLeaseFile(name, format); err != nil {
		return fmt.Errorf("could not read lease file: %w", err)
	}
	clientInfoFiles[name] = format
	return mt.watcher.Add(name)
}

// GetClientInfoByMac returns ClientInfo for the client associated with the given MAC address.
func (mt *MacTable) GetClientInfoByMac(mac string) *ctrld.ClientInfo {
	if mac == "" {
		return nil
	}
	val, ok := mt.mac.Load(mac)
	if !ok {
		return nil
	}
	return val.(*ctrld.ClientInfo)
}

// WatchLeaseFiles watches changes happens in dnsmasq/dhcpd
// lease files, perform updating to mac table if necessary.
func (mt *MacTable) WatchLeaseFiles() {
	if mt.watcher == nil {
		return
	}
	timer := time.NewTicker(time.Minute * 5)
	for {
		select {
		case <-timer.C:
			for _, name := range mt.watcher.WatchList() {
				format := clientInfoFiles[name]
				if err := mt.readLeaseFile(name, format); err != nil {
					ctrld.ProxyLog.Err(err).Str("file", name).Msg("failed to update lease file")
				}
			}
		case event, ok := <-mt.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				format := clientInfoFiles[event.Name]
				if err := mt.readLeaseFile(event.Name, format); err != nil && !os.IsNotExist(err) {
					ctrld.ProxyLog.Err(err).Str("file", event.Name).Msg("leases file changed but failed to update client info")
				}
			}
		case err, ok := <-mt.watcher.Errors:
			if !ok {
				return
			}
			ctrld.ProxyLog.Err(err).Msg("could not watch client info file")
		}
	}
}

// readLeaseFile reads the lease file with given format, saving client information to mac table.
func (mt *MacTable) readLeaseFile(name string, format ctrld.LeaseFileFormat) error {
	switch format {
	case ctrld.Dnsmasq:
		return mt.dnsmasqReadClientInfoFile(name)
	case ctrld.IscDhcpd:
		return mt.iscDHCPReadClientInfoFile(name)
	}
	return fmt.Errorf("unsupported format: %s, file: %s", format, name)
}

// dnsmasqReadClientInfoFile populates mac table with client info reading from dnsmasq lease file.
func (mt *MacTable) dnsmasqReadClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return mt.dnsmasqReadClientInfoReader(f)

}

// dnsmasqReadClientInfoReader likes ctrld.Dnsmasq, but reading from an io.Reader instead of file.
func (mt *MacTable) dnsmasqReadClientInfoReader(reader io.Reader) error {
	return lineread.Reader(reader, func(line []byte) error {
		fields := bytes.Fields(line)
		if len(fields) < 4 {
			return nil
		}
		mac := string(fields[1])
		if _, err := net.ParseMAC(mac); err != nil {
			// The second field is not a mac, skip.
			return nil
		}
		ip := normalizeIP(string(fields[2]))
		if net.ParseIP(ip) == nil {
			log.Printf("invalid ip address entry: %q", ip)
			ip = ""
		}
		hostname := string(fields[3])
		mt.mac.Store(mac, &ctrld.ClientInfo{Mac: mac, IP: ip, Hostname: hostname})
		return nil
	})
}

// iscDHCPReadClientInfoFile populates mac table with client info reading from isc-dhcpd lease file.
func (mt *MacTable) iscDHCPReadClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return mt.iscDHCPReadClientInfoReader(f)
}

// iscDHCPReadClientInfoReader likes ctrld.IscDhcpd, but reading from an io.Reader instead of file.
func (mt *MacTable) iscDHCPReadClientInfoReader(reader io.Reader) error {
	s := bufio.NewScanner(reader)
	var ip, mac, hostname string
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "}") {
			if mac != "" {
				mt.mac.Store(mac, &ctrld.ClientInfo{Mac: mac, IP: ip, Hostname: hostname})
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
				log.Printf("invalid ip address entry: %q", ip)
				ip = ""
			}
		case "hardware":
			if len(fields) >= 3 {
				mac = strings.ToLower(strings.TrimRight(fields[2], ";"))
				if _, err := net.ParseMAC(mac); err != nil {
					// Invalid mac, skip.
					mac = ""
				}
			}
		case "client-hostname":
			hostname = strings.Trim(fields[1], `";`)
		}
	}
	return nil
}

// normalizeIP normalizes the ip parsed from dnsmasq/dhcpd lease file.
func normalizeIP(in string) string {
	// dnsmasq may put ip with interface index in lease file, strip it here.
	ip, _, found := strings.Cut(in, "%")
	if found {
		return ip
	}
	return in
}

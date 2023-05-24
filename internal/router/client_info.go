package router

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/util/lineread"

	"github.com/Control-D-Inc/ctrld"
)

var clientInfoFiles = []string{
	"/tmp/dnsmasq.leases",                  // ddwrt
	"/tmp/dhcp.leases",                     // openwrt
	"/var/lib/misc/dnsmasq.leases",         // merlin
	"/mnt/data/udapi-config/dnsmasq.lease", // UDM Pro
	"/data/udapi-config/dnsmasq.lease",     // UDR
	"/etc/dhcpd/dhcpd-leases.log",          // Synology
}

func (r *router) watchClientInfoTable() {
	if r.watcher == nil {
		return
	}
	timer := time.NewTicker(time.Minute * 5)
	for {
		select {
		case <-timer.C:
			for _, name := range r.watcher.WatchList() {
				_ = readClientInfoFile(name)
			}
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				if err := readClientInfoFile(event.Name); err != nil && !os.IsNotExist(err) {
					log.Println("could not read client info file:", err)
				}
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}

func Stop() error {
	if Name() == "" {
		return nil
	}
	r := routerPlatform.Load()
	if r.watcher != nil {
		if err := r.watcher.Close(); err != nil {
			return err
		}
	}
	return nil
}

func GetClientInfoByMac(mac string) *ctrld.ClientInfo {
	if mac == "" {
		return nil
	}
	_ = Name()
	r := routerPlatform.Load()
	val, ok := r.mac.Load(mac)
	if !ok {
		return nil
	}
	return val.(*ctrld.ClientInfo)
}

func readClientInfoFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return readClientInfoReader(f)

}

func readClientInfoReader(reader io.Reader) error {
	r := routerPlatform.Load()
	return lineread.Reader(reader, func(line []byte) error {
		fields := bytes.Fields(line)
		if len(fields) != 5 {
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
		r.mac.Store(mac, &ctrld.ClientInfo{Mac: mac, IP: ip, Hostname: hostname})
		return nil
	})
}

func normalizeIP(in string) string {
	// dnsmasq may put ip with interface index in lease file, strip it here.
	ip, _, found := strings.Cut(in, "%")
	if found {
		return ip
	}
	return in
}

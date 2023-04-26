package router

import (
	"bytes"
	"log"
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
	r := routerPlatform.Load()
	return lineread.File(name, func(line []byte) error {
		fields := bytes.Fields(line)
		mac := string(fields[1])
		ip := normalizeIP(string(fields[2]))
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

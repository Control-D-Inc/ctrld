package clientinfo

import (
	"net/netip"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/jaytaylor/go-hostsfile"

	"github.com/Control-D-Inc/ctrld"
)

const (
	ipv4LocalhostName = "localhost"
	ipv6LocalhostName = "ip6-localhost"
	ipv6LoopbackName  = "ip6-loopback"
)

// hostsFile provides client discovery functionality using system hosts file.
type hostsFile struct {
	watcher *fsnotify.Watcher
	mu      sync.Mutex
	m       map[string][]string
}

// init performs initialization works, which is necessary before hostsFile can be fully operated.
func (hf *hostsFile) init() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	hf.watcher = watcher
	if err := hf.watcher.Add(hostsfile.HostsPath); err != nil {
		return err
	}
	m, err := hostsfile.ParseHosts(hostsfile.ReadHostsFile())
	if err != nil {
		return err
	}
	hf.mu.Lock()
	hf.m = m
	hf.mu.Unlock()
	return nil
}

// refresh reloads hosts file entries.
func (hf *hostsFile) refresh() error {
	m, err := hostsfile.ParseHosts(hostsfile.ReadHostsFile())
	if err != nil {
		return err
	}
	hf.mu.Lock()
	hf.m = m
	hf.mu.Unlock()
	return nil
}

// watchChanges watches and updates hosts file data if any changes happens.
func (hf *hostsFile) watchChanges() {
	if hf.watcher == nil {
		return
	}
	for {
		select {
		case event, ok := <-hf.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Chmod) || event.Has(fsnotify.Remove) {
				if err := hf.refresh(); err != nil && !os.IsNotExist(err) {
					ctrld.ProxyLogger.Load().Err(err).Msg("hosts file changed but failed to update client info")
				}
			}
		case err, ok := <-hf.watcher.Errors:
			if !ok {
				return
			}
			ctrld.ProxyLogger.Load().Err(err).Msg("could not watch client info file")
		}
	}

}

// LookupHostnameByIP returns hostname for given IP from current hosts file entries.
func (hf *hostsFile) LookupHostnameByIP(ip string) string {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	if names := hf.m[ip]; len(names) > 0 {
		isLoopback := ip == "127.0.0.1" || ip == "::1"
		for _, hostname := range names {
			name := normalizeHostname(hostname)
			// Ignoring ipv4/ipv6 loopback entry.
			if isLoopback && isLocalhostName(name) {
				continue
			}
			return name
		}
	}
	return ""
}

// LookupHostnameByMac returns hostname for given Mac from current hosts file entries.
func (hf *hostsFile) LookupHostnameByMac(mac string) string {
	return ""
}

// String returns human-readable format of hostsFile.
func (hf *hostsFile) String() string {
	return "hosts"
}

func (hf *hostsFile) lookupIPByHostname(name string, v6 bool) string {
	if hf == nil {
		return ""
	}
	hf.mu.Lock()
	defer hf.mu.Unlock()
	for addr, names := range hf.m {
		if ip, err := netip.ParseAddr(addr); err == nil && !ip.IsLoopback() {
			for _, n := range names {
				if n == name && ip.Is6() == v6 {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// isLocalhostName reports whether the given hostname represents localhost.
func isLocalhostName(hostname string) bool {
	switch hostname {
	case ipv4LocalhostName, ipv6LocalhostName, ipv6LoopbackName:
		return true
	default:
		return false
	}
}

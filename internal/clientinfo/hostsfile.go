package clientinfo

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/jaytaylor/go-hostsfile"

	"github.com/Control-D-Inc/ctrld"
)

const (
	ipv4LocalhostName   = "localhost"
	ipv6LocalhostName   = "ip6-localhost"
	ipv6LoopbackName    = "ip6-loopback"
	hostEntriesConfPath = "/var/unbound/host_entries.conf"
)

// hostsFile provides client discovery functionality using system hosts file.
type hostsFile struct {
	watcher *fsnotify.Watcher
	mu      sync.Mutex
	m       map[string][]string
	logger  *ctrld.Logger
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
	// Conservatively adding hostEntriesConfPath, since it is not available everywhere.
	_ = hf.watcher.Add(hostEntriesConfPath)
	return hf.refresh()
}

// refresh reloads hosts file entries.
func (hf *hostsFile) refresh() error {
	m, err := hostsfile.ParseHosts(hostsfile.ReadHostsFile())
	if err != nil {
		return err
	}
	hf.mu.Lock()
	hf.m = m
	// override hosts file with host_entries.conf content if present.
	hem, err := parseHostEntriesConf(hostEntriesConfPath)
	if err != nil && !os.IsNotExist(err) {
		hf.logger.Debug().Err(err).Msg("could not read host_entries.conf file")
	}
	for k, v := range hem {
		hf.m[k] = v
	}
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
					hf.logger.Err(err).Msg("hosts file changed but failed to update client info")
				}
			}
		case err, ok := <-hf.watcher.Errors:
			if !ok {
				return
			}
			hf.logger.Err(err).Msg("could not watch client info file")
		}
	}

}

// LookupHostnameByIP returns hostname for given IP from current hosts file entries.
func (hf *hostsFile) LookupHostnameByIP(ip string) string {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	if names := hf.m[ip]; len(names) > 0 {
		isLoopback := ip == ipV4Loopback || ip == ipv6Loopback
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

// parseHostEntriesConf parses host_entries.conf file and returns parsed result.
func parseHostEntriesConf(path string) (map[string][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseHostEntriesConfFromReader(bytes.NewReader(b)), nil
}

// parseHostEntriesConfFromReader is like parseHostEntriesConf, but read from an io.Reader instead of file.
func parseHostEntriesConfFromReader(r io.Reader) map[string][]string {
	hostsMap := map[string][]string{}
	scanner := bufio.NewScanner(r)

	localZone := ""
	for scanner.Scan() {
		line := scanner.Text()
		if after, found := strings.CutPrefix(line, "local-zone:"); found {
			after = strings.TrimSpace(after)
			fields := strings.Fields(after)
			if len(fields) > 1 {
				localZone = strings.Trim(fields[0], `"`)
			}
			continue
		}
		// Only read "local-data-ptr: ..." line, it has all necessary information.
		after, found := strings.CutPrefix(line, "local-data-ptr:")
		if !found {
			continue
		}
		after = strings.TrimSpace(after)
		after = strings.Trim(after, `"`)
		fields := strings.Fields(after)
		if len(fields) != 2 {
			continue
		}
		ip := fields[0]
		name := strings.TrimSuffix(fields[1], "."+localZone)
		hostsMap[ip] = append(hostsMap[ip], name)
	}
	return hostsMap
}

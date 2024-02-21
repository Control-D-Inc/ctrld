package cli

import (
	"net"
	"net/netip"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

const (
	resolvConfPath            = "/etc/resolv.conf"
	resolvConfBackupFailedMsg = "open /etc/resolv.pre-ctrld-backup.conf: read-only file system"
)

// watchResolvConf watches any changes to /etc/resolv.conf file,
// and reverting to the original config set by ctrld.
func watchResolvConf(iface *net.Interface, ns []netip.Addr, setDnsFn func(iface *net.Interface, ns []netip.Addr) error) {
	mainLog.Load().Debug().Msg("start watching /etc/resolv.conf file")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not create watcher for /etc/resolv.conf")
		return
	}
	defer watcher.Close()

	// We watch /etc instead of /etc/resolv.conf directly,
	// see: https://github.com/fsnotify/fsnotify#watching-a-file-doesnt-work-well
	watchDir := filepath.Dir(resolvConfPath)
	if err := watcher.Add(watchDir); err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not add /etc/resolv.conf to watcher list")
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Name != resolvConfPath { // skip if not /etc/resolv.conf changes.
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				mainLog.Load().Debug().Msg("/etc/resolv.conf changes detected, reverting to ctrld setting")
				if err := watcher.Remove(watchDir); err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to pause watcher")
					continue
				}
				if err := setDnsFn(iface, ns); err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to revert /etc/resolv.conf changes")
				}
				if err := watcher.Add(watchDir); err != nil {
					mainLog.Load().Error().Err(err).Msg("failed to continue running watcher")
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			mainLog.Load().Err(err).Msg("could not get event for /etc/resolv.conf")
		}
	}
}

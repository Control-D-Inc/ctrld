package cli

import (
	"net"
	"net/netip"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// watchResolvConf watches any changes to /etc/resolv.conf file,
// and reverting to the original config set by ctrld.
func (p *prog) watchResolvConf(iface *net.Interface, ns []netip.Addr, setDnsFn func(iface *net.Interface, ns []netip.Addr) error) {
	resolvConfPath := "/etc/resolv.conf"
	// Evaluating symbolics link to watch the target file that /etc/resolv.conf point to.
	if rp, _ := filepath.EvalSymlinks(resolvConfPath); rp != "" {
		resolvConfPath = rp
	}
	mainLog.Load().Debug().Msgf("start watching %s file", resolvConfPath)
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
		mainLog.Load().Warn().Err(err).Msgf("could not add %s to watcher list", watchDir)
		return
	}

	for {
		select {
		case <-p.dnsWatcherStopCh:
			return
		case <-p.stopCh:
			mainLog.Load().Debug().Msgf("stopping watcher for %s", resolvConfPath)
			return
		case event, ok := <-watcher.Events:
			if p.leakingQueryReset.Load() {
				return
			}
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

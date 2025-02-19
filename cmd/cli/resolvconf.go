package cli

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// parseResolvConfNameservers reads the resolv.conf file and returns the nameservers found.
// Returns nil if no nameservers are found.
func (p *prog) parseResolvConfNameservers(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse the file for "nameserver" lines
	var currentNS []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "nameserver") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentNS = append(currentNS, parts[1])
			}
		}
	}

	return currentNS, nil
}

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
			if p.recoveryRunning.Load() {
				return
			}
			if !ok {
				return
			}
			if event.Name != resolvConfPath { // skip if not /etc/resolv.conf changes.
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				mainLog.Load().Debug().Msgf("/etc/resolv.conf changes detected, reading changes...")

				// Convert expected nameservers to strings for comparison
				expectedNS := make([]string, len(ns))
				for i, addr := range ns {
					expectedNS[i] = addr.String()
				}

				var foundNS []string
				var err error

				maxRetries := 1
				for retry := 0; retry < maxRetries; retry++ {
					foundNS, err = p.parseResolvConfNameservers(resolvConfPath)
					if err != nil {
						mainLog.Load().Error().Err(err).Msg("failed to read resolv.conf content")
						break
					}

					// If we found nameservers, break out of retry loop
					if len(foundNS) > 0 {
						break
					}

					// Only retry if we found no nameservers
					if retry < maxRetries-1 {
						mainLog.Load().Debug().Msgf("resolv.conf has no nameserver entries, retry %d/%d in 2 seconds", retry+1, maxRetries)
						select {
						case <-p.stopCh:
							return
						case <-p.dnsWatcherStopCh:
							return
						case <-time.After(2 * time.Second):
							continue
						}
					} else {
						mainLog.Load().Debug().Msg("resolv.conf remained empty after all retries")
					}
				}

				// If we found nameservers, check if they match what we expect
				if len(foundNS) > 0 {
					// Check if the nameservers match exactly what we expect
					matches := len(foundNS) == len(expectedNS)
					if matches {
						for i := range foundNS {
							if foundNS[i] != expectedNS[i] {
								matches = false
								break
							}
						}
					}

					mainLog.Load().Debug().
						Strs("found", foundNS).
						Strs("expected", expectedNS).
						Bool("matches", matches).
						Msg("checking nameservers")

					// Only revert if the nameservers don't match
					if !matches {
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

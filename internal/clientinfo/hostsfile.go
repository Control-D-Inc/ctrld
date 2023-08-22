package clientinfo

import (
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/txn2/txeh"

	"github.com/Control-D-Inc/ctrld"
)

// hostsFile provides client discovery functionality using system hosts file.
type hostsFile struct {
	h       *txeh.Hosts
	watcher *fsnotify.Watcher
}

// init performs initialization works, which is necessary before hostsFile can be fully operated.
func (hf *hostsFile) init() error {
	h, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	hf.h = h
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	hf.watcher = watcher
	if err := hf.watcher.Add(hf.h.ReadFilePath); err != nil {
		return err
	}
	return nil
}

// refresh reloads hosts file entries.
func (hf *hostsFile) refresh() error {
	return hf.h.Reload()
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
	hf.h.Lock()
	defer hf.h.Unlock()

	if names := hf.h.ListHostsByIP(ip); len(names) > 0 {
		return names[0]
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

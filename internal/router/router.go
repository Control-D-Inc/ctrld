package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/service"
	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld"
)

const (
	OpenWrt = "openwrt"
	DDWrt   = "ddwrt"
	Merlin  = "merlin"
	Ubios   = "ubios"
)

// ErrNotSupported reports the current router is not supported error.
var ErrNotSupported = errors.New("unsupported platform")

var routerPlatform atomic.Pointer[router]

type router struct {
	name           string
	sendClientInfo bool
	mac            sync.Map
	watcher        *fsnotify.Watcher
}

// SupportedPlatforms return all platforms that can be configured to run with ctrld.
func SupportedPlatforms() []string {
	return []string{DDWrt, Merlin, OpenWrt, Ubios}
}

var configureFunc = map[string]func() error{
	DDWrt:   setupDDWrt,
	Merlin:  setupMerlin,
	OpenWrt: setupOpenWrt,
	Ubios:   setupUbiOS,
}

// Configure configures things for running ctrld on the router.
func Configure(c *ctrld.Config) error {
	name := Name()
	switch name {
	case DDWrt, Merlin, OpenWrt, Ubios:
		if c.HasUpstreamSendClientInfo() {
			r := routerPlatform.Load()
			r.sendClientInfo = true
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				return err
			}
			r.watcher = watcher
			go r.watchClientInfoTable()
			for _, file := range clientInfoFiles {
				_ = readClientInfoFile(file)
				_ = r.watcher.Add(file)
			}
		}
		configure := configureFunc[name]
		if err := configure(); err != nil {
			return err
		}
		return nil
	default:
		return ErrNotSupported
	}
}

// ConfigureService performs necessary setup for running ctrld as a service on router.
func ConfigureService(sc *service.Config) error {
	name := Name()
	switch name {
	case DDWrt:
		if !ddwrtJff2Enabled() {
			return ddwrtJffs2NotEnabledErr
		}
	case OpenWrt:
		sc.Option["SysvScript"] = openWrtScript
	case Merlin, Ubios:
	}
	return nil
}

// PreStart blocks until the router is ready for running ctrld.
func PreStart() (err error) {
	if Name() != DDWrt {
		return nil
	}

	pidFile := "/tmp/ctrld.pid"
	// On Merlin, NTP may out of sync, so waiting for it to be ready.
	//
	// Remove pid file and trigger dnsmasq restart, so NTP can resolve
	// server name and perform time synchronization.
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("PreStart: os.Readfile: %w", err)
	}
	if err := os.Remove(pidFile); err != nil {
		return fmt.Errorf("PreStart: os.Remove: %w", err)
	}
	defer func() {
		if werr := os.WriteFile(pidFile, pid, 0600); werr != nil {
			err = errors.Join(err, werr)
			return
		}
		if rerr := merlinRestartDNSMasq(); rerr != nil {
			err = errors.Join(err, rerr)
			return
		}
	}()
	if err := merlinRestartDNSMasq(); err != nil {
		return fmt.Errorf("PreStart: merlinRestartDNSMasq: %w", err)
	}

	// Wait until `ntp_read=1` set.
	b := backoff.NewBackoff("PreStart", func(format string, args ...any) {}, 10*time.Second)
	for {
		out, err := nvram("get", "ntp_ready")
		if err != nil {
			return fmt.Errorf("PreStart: nvram: %w", err)
		}
		if out == "1" {
			return nil
		}
		b.BackOff(context.Background(), errors.New("ntp not ready"))
	}
}

// PostInstall performs task after installing ctrld on router.
func PostInstall() error {
	name := Name()
	switch name {
	case DDWrt:
		return postInstallDDWrt()
	case Merlin:
		return postInstallMerlin()
	case OpenWrt:
		return postInstallOpenWrt()
	case Ubios:
		return postInstallUbiOS()
	}
	return nil
}

// Cleanup cleans ctrld setup on the router.
func Cleanup() error {
	name := Name()
	switch name {
	case DDWrt:
		return cleanupDDWrt()
	case Merlin:
		return cleanupMerlin()
	case OpenWrt:
		return cleanupOpenWrt()
	case Ubios:
		return cleanupUbiOS()
	}
	return nil
}

// ListenAddress returns the listener address of ctrld on router.
func ListenAddress() string {
	name := Name()
	switch name {
	case DDWrt, Merlin, OpenWrt, Ubios:
		return "127.0.0.1:5354"
	}
	return ""
}

// Name returns name of the router platform.
func Name() string {
	if r := routerPlatform.Load(); r != nil {
		return r.name
	}
	r := &router{}
	r.name = distroName()
	routerPlatform.Store(r)
	return r.name
}

func distroName() string {
	switch {
	case bytes.HasPrefix(uname(), []byte("DD-WRT")):
		return DDWrt
	case bytes.HasPrefix(uname(), []byte("ASUSWRT-Merlin")):
		return Merlin
	case haveFile("/etc/openwrt_version"):
		return OpenWrt
	case haveDir("/data/unifi"):
		return Ubios
	}
	return ""
}

func haveFile(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func haveDir(dir string) bool {
	fi, _ := os.Stat(dir)
	return fi != nil && fi.IsDir()
}

func uname() []byte {
	out, _ := exec.Command("uname", "-o").Output()
	return out
}

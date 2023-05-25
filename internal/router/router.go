package router

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
)

const (
	OpenWrt  = "openwrt"
	DDWrt    = "ddwrt"
	Merlin   = "merlin"
	Ubios    = "ubios"
	Synology = "synology"
	Tomato   = "tomato"
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

// IsSupported reports whether the given platform is supported by ctrld.
func IsSupported(platform string) bool {
	switch platform {
	case DDWrt, Merlin, OpenWrt, Ubios, Synology, Tomato:
		return true
	}
	return false
}

// SupportedPlatforms return all platforms that can be configured to run with ctrld.
func SupportedPlatforms() []string {
	return []string{DDWrt, Merlin, OpenWrt, Ubios, Synology, Tomato}
}

var configureFunc = map[string]func() error{
	DDWrt:    setupDDWrt,
	Merlin:   setupMerlin,
	OpenWrt:  setupOpenWrt,
	Ubios:    setupUbiOS,
	Synology: setupSynology,
	Tomato:   setupTomato,
}

// Configure configures things for running ctrld on the router.
func Configure(c *ctrld.Config) error {
	name := Name()
	switch name {
	case DDWrt, Merlin, OpenWrt, Ubios, Synology, Tomato:
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
			return errDdwrtJffs2NotEnabled
		}
	case OpenWrt:
		sc.Option["SysvScript"] = openWrtScript
	case Merlin, Ubios, Synology, Tomato:
	}
	return nil
}

// PreStart blocks until the router is ready for running ctrld.
func PreStart() (err error) {
	// On some routers, NTP may out of sync, so waiting for it to be ready.
	switch Name() {
	case Merlin:
		return merlinPreStart()
	case Tomato:
		return tomatoPreStart()
	default:
		return nil
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
	case Synology:
		return postInstallSynology()
	case Tomato:
		return postInstallTomato()
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
	case Synology:
		return cleanupSynology()
	case Tomato:
		return cleanupTomato()
	}
	return nil
}

// ListenAddress returns the listener address of ctrld on router.
func ListenAddress() string {
	name := Name()
	switch name {
	case DDWrt, Merlin, OpenWrt, Ubios, Synology, Tomato:
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
	case bytes.HasPrefix(unameO(), []byte("DD-WRT")):
		return DDWrt
	case bytes.HasPrefix(unameO(), []byte("ASUSWRT-Merlin")):
		return Merlin
	case haveFile("/etc/openwrt_version"):
		return OpenWrt
	case haveDir("/data/unifi"):
		return Ubios
	case bytes.HasPrefix(unameU(), []byte("synology")):
		return Synology
	case bytes.HasPrefix(unameO(), []byte("Tomato")):
		return Tomato
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

func unameO() []byte {
	out, _ := exec.Command("uname", "-o").Output()
	return out
}

func unameU() []byte {
	out, _ := exec.Command("uname", "-u").Output()
	return out
}

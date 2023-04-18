package router

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"

	"github.com/kardianos/service"

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
	name string
}

// SupportedPlatforms return all platforms that can be configured to run with ctrld.
func SupportedPlatforms() []string {
	return []string{DDWrt, Merlin, OpenWrt, Ubios}
}

// Configure configures things for running ctrld on the router.
func Configure(c *ctrld.Config) error {
	name := Name()
	switch name {
	case DDWrt:
		return setupDDWrt()
	case Merlin:
		return setupMerlin()
	case OpenWrt:
		return setupOpenWrt()
	case Ubios:
		return setupUbiOS()
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

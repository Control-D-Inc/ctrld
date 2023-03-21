package router

import (
	"bytes"
	"errors"
	"fmt"
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
	case OpenWrt:
		return setupOpenWrt()
	case DDWrt, Merlin, Ubios:
	default:
		return ErrNotSupported
	}
	// TODO: implement all supported platforms.
	fmt.Printf("Configuring router for: %s\n", name)
	return nil
}

// ConfigureService performs necessary setup for running ctrld as a service on router.
func ConfigureService(sc *service.Config) {
	name := Name()
	switch name {
	case OpenWrt:
		sc.Option["SysvScript"] = openWrtScript
	case DDWrt, Merlin, Ubios:
	}
}

// PostInstall performs task after installing ctrld on router.
func PostInstall() error {
	name := Name()
	switch name {
	case OpenWrt:
		return postInstallOpenWrt()
	case DDWrt, Merlin, Ubios:
	}
	return nil
}

// Cleanup cleans ctrld setup on the router.
func Cleanup() error {
	name := Name()
	switch name {
	case OpenWrt:
		return cleanupOpenWrt()
	case DDWrt, Merlin, Ubios:
	}
	return nil
}

// ListenAddress returns the listener address of ctrld on router.
func ListenAddress() string {
	name := Name()
	switch name {
	case OpenWrt:
		return ":53"
	case DDWrt, Merlin, Ubios:
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

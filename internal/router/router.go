package router

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"

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

var routerAtomic atomic.Pointer[router]

type router struct {
	name string
}

// SupportedPlatforms return all platforms that can be configured to run with ctrld.
func SupportedPlatforms() []string {
	return []string{DDWrt, Merlin, OpenWrt, Ubios}
}

// Configure change the given *ctrld.Config for running on the router.
func Configure(c *ctrld.Config) error {
	name := Name()
	switch name {
	case DDWrt, Merlin, OpenWrt, Ubios:
	default:
		return ErrNotSupported
	}
	// TODO: implement all supported platforms.
	fmt.Printf("Configuring router for: %s\n", name)
	return nil
}

// Name returns name of the router platform.
func Name() string {
	if r := routerAtomic.Load(); r != nil {
		return r.name
	}
	r := &router{}
	r.name = distroName()
	routerAtomic.Store(r)
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

package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/kardianos/service"
	"tailscale.com/logtail/backoff"

	"github.com/Control-D-Inc/ctrld"
)

const (
	DDWrt     = "ddwrt"
	EdgeOS    = "edgeos"
	Firewalla = "firewalla"
	Merlin    = "merlin"
	OpenWrt   = "openwrt"
	Pfsense   = "pfsense"
	Synology  = "synology"
	Tomato    = "tomato"
	Ubios     = "ubios"
)

// ErrNotSupported reports the current router is not supported error.
var ErrNotSupported = errors.New("unsupported platform")

var routerPlatform atomic.Pointer[router]

type router struct {
	name           string
	sendClientInfo bool
}

// IsSupported reports whether the given platform is supported by ctrld.
func IsSupported(platform string) bool {
	switch platform {
	case DDWrt,
		EdgeOS,
		Firewalla,
		Merlin,
		OpenWrt,
		Pfsense,
		Synology,
		Tomato,
		Ubios:
		return true
	}
	return false
}

// SupportedPlatforms return all platforms that can be configured to run with ctrld.
func SupportedPlatforms() []string {
	return []string{
		DDWrt,
		EdgeOS,
		Firewalla,
		Merlin,
		OpenWrt,
		Pfsense,
		Synology,
		Tomato,
		Ubios,
	}
}

var configureFunc = map[string]func() error{
	DDWrt:     setupDDWrt,
	EdgeOS:    setupEdgeOS,
	Firewalla: setupFirewalla,
	Merlin:    setupMerlin,
	OpenWrt:   setupOpenWrt,
	Pfsense:   setupPfsense,
	Synology:  setupSynology,
	Tomato:    setupTomato,
	Ubios:     setupUbiOS,
}

// Configure configures things for running ctrld on the router.
func Configure(c *ctrld.Config) error {
	name := Name()
	switch name {
	case DDWrt,
		EdgeOS,
		Firewalla,
		Merlin,
		OpenWrt,
		Pfsense,
		Synology,
		Tomato,
		Ubios:
		if c.HasUpstreamSendClientInfo() {
			r := routerPlatform.Load()
			r.sendClientInfo = true
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
	case Pfsense:
		sc.Option["SysvScript"] = pfsenseInitScript
	case EdgeOS, Firewalla, Merlin, Synology, Tomato, Ubios:
	}
	return nil
}

// PreRun blocks until the router is ready for running ctrld.
func PreRun() (err error) {
	// On some routers, NTP may out of sync, so waiting for it to be ready.
	switch Name() {
	case Merlin, Tomato:
		// Wait until `ntp_ready=1` set.
		b := backoff.NewBackoff("PreRun", func(format string, args ...any) {}, 10*time.Second)
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
	default:
		return nil
	}
}

// PostInstall performs task after installing ctrld on router.
func PostInstall(svc *service.Config) error {
	name := Name()
	switch name {
	case DDWrt:
		return postInstallDDWrt()
	case EdgeOS:
		return postInstallEdgeOS()
	case Firewalla:
		return postInstallFirewalla()
	case Merlin:
		return postInstallMerlin()
	case OpenWrt:
		return postInstallOpenWrt()
	case Pfsense:
		return postInstallPfsense(svc)
	case Synology:
		return postInstallSynology()
	case Tomato:
		return postInstallTomato()
	case Ubios:
		return postInstallUbiOS()
	}
	return nil
}

// PostUninstall performs task after uninstalling ctrld on router.
func PostUninstall(svc *service.Config) error {
	name := Name()
	switch name {
	case DDWrt:
	case EdgeOS:
	case Firewalla:
		return postUninstallFirewalla()
	case Merlin:
	case OpenWrt:
	case Pfsense:
	case Synology:
	case Tomato:
	case Ubios:
	}
	return nil
}

// Cleanup cleans ctrld setup on the router.
func Cleanup(svc *service.Config) error {
	name := Name()
	switch name {
	case DDWrt:
		return cleanupDDWrt()
	case EdgeOS:
		return cleanupEdgeOS()
	case Firewalla:
		return cleanupFirewalla()
	case Merlin:
		return cleanupMerlin()
	case OpenWrt:
		return cleanupOpenWrt()
	case Pfsense:
		return cleanupPfsense(svc)
	case Synology:
		return cleanupSynology()
	case Tomato:
		return cleanupTomato()
	case Ubios:
		return cleanupUbiOS()
	}
	return nil
}

// ListenIP returns the listener IP of ctrld on router.
func ListenIP() string {
	return "127.0.0.1"
}

// ListenPort returns the listener port of ctrld on router.
func ListenPort() int {
	name := Name()
	switch name {
	case DDWrt, Firewalla, Merlin, OpenWrt, Synology, Tomato, Ubios:
		return 5354
	case Pfsense:
		// On pfsense, we run ctrld as DNS resolver.
	}
	return 53
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
	case haveDir("/config/scripts/post-config.d"):
		checkUSG()
		return EdgeOS
	case haveFile("/etc/ubnt/init/vyatta-router"):
		checkUSG()
		return EdgeOS // For 2.x
	case isPfsense():
		return Pfsense
	case haveFile("/etc/firewalla_release"):
		return Firewalla
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

func isPfsense() bool {
	b, err := os.ReadFile("/etc/platform")
	return err == nil && bytes.HasPrefix(b, []byte("pfSense"))
}

func checkUSG() {
	out, _ := exec.Command("mca-cli-op", "info").Output()
	isUSG = bytes.Contains(out, []byte("UniFi-Gateway-"))
}

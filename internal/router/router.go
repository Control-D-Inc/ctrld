package router

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	"github.com/Control-D-Inc/ctrld/internal/router/ddwrt"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/edgeos"
	"github.com/Control-D-Inc/ctrld/internal/router/firewalla"
	"github.com/Control-D-Inc/ctrld/internal/router/merlin"
	"github.com/Control-D-Inc/ctrld/internal/router/openwrt"
	"github.com/Control-D-Inc/ctrld/internal/router/pfsense"
	"github.com/Control-D-Inc/ctrld/internal/router/synology"
	"github.com/Control-D-Inc/ctrld/internal/router/tomato"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

// Service is the interface to manage ctrld service on router.
type Service interface {
	ConfigureService(*service.Config) error
	Install(*service.Config) error
	Uninstall(*service.Config) error
}

// Router is the interface for managing ctrld running on router.
type Router interface {
	Service

	PreRun() error
	Setup() error
	Cleanup() error
}

// New returns new Router interface.
func New(cfg *ctrld.Config) Router {
	switch Name() {
	case ddwrt.Name:
		return ddwrt.New(cfg)
	case merlin.Name:
		return merlin.New(cfg)
	case openwrt.Name:
		return openwrt.New(cfg)
	case edgeos.Name:
		return edgeos.New(cfg)
	case ubios.Name:
		return ubios.New(cfg)
	case synology.Name:
		return synology.New(cfg)
	case tomato.Name:
		return tomato.New(cfg)
	case pfsense.Name:
		return pfsense.New(cfg)
	case firewalla.Name:
		return firewalla.New(cfg)
	}
	return &dummy{}
}

// IsGLiNet reports whether the router is an GL.iNet router.
func IsGLiNet() bool {
	if Name() != openwrt.Name {
		return false
	}
	buf, _ := os.ReadFile("/proc/version")
	// The output of /proc/version contains "(glinet@glinet)".
	return bytes.Contains(buf, []byte(" (glinet"))
}

// IsOldOpenwrt reports whether the router is an "old" version of Openwrt,
// aka versions which don't have "service" command.
func IsOldOpenwrt() bool {
	if Name() != openwrt.Name {
		return false
	}
	cmd, _ := exec.LookPath("service")
	return cmd == ""
}

var routerPlatform atomic.Pointer[router]

type router struct {
	name           string
	sendClientInfo bool
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

// DefaultInterfaceName returns the default interface name of the current router.
func DefaultInterfaceName() string {
	switch Name() {
	case ubios.Name:
		return "lo"
	}
	return ""
}

// LocalResolverIP returns the IP that could be used as nameserver in /etc/resolv.conf file.
func LocalResolverIP() string {
	var iface string
	switch Name() {
	case edgeos.Name:
		// On EdgeOS, dnsmasq is run with "--local-service", so we need to get
		// the proper interface from dnsmasq config.
		if name, _ := dnsmasq.InterfaceNameFromConfig("/etc/dnsmasq.conf"); name != "" {
			iface = name
		}
	case firewalla.Name:
		// On Firewalla, the lo interface is excluded in all dnsmasq settings of all interfaces.
		// Thus, we use "br0" as the nameserver in /etc/resolv.conf file.
		iface = "br0"
	}
	if netIface, _ := net.InterfaceByName(iface); netIface != nil {
		addrs, _ := netIface.Addrs()
		for _, addr := range addrs {
			if netIP, ok := addr.(*net.IPNet); ok && netIP.IP.To4() != nil {
				return netIP.IP.To4().String()
			}
		}
	}
	return ""
}

// HomeDir returns the home directory of ctrld on current router.
func HomeDir() (string, error) {
	switch Name() {
	case ddwrt.Name, merlin.Name, tomato.Name:
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.Dir(exe), nil
	}
	return "", nil
}

// CertPool returns the system certificate pool of the current router.
func CertPool() *x509.CertPool {
	if Name() == ddwrt.Name {
		return certs.CACertPool()
	}
	return nil
}

// CanListenLocalhost reports whether the ctrld can listen on localhost with current host.
func CanListenLocalhost() bool {
	switch {
	case Name() == firewalla.Name:
		return false
	default:
		return true
	}
}

// ServiceDependencies returns list of dependencies that ctrld services needs on this router.
// See https://pkg.go.dev/github.com/kardianos/service#Config for list format.
func ServiceDependencies() []string {
	if Name() == edgeos.Name {
		// On EdeOS, ctrld needs to start after vyatta-dhcpd, so it can read leases file.
		return []string{
			"Wants=vyatta-dhcpd.service",
			"After=vyatta-dhcpd.service",
			"Wants=dnsmasq.service",
		}
	}
	return nil
}

func distroName() string {
	switch {
	case bytes.HasPrefix(unameO(), []byte("DD-WRT")):
		return ddwrt.Name
	case bytes.HasPrefix(unameO(), []byte("ASUSWRT-Merlin")):
		return merlin.Name
	case haveFile("/etc/openwrt_version"):
		return openwrt.Name
	case haveDir("/data/unifi"):
		return ubios.Name
	case bytes.HasPrefix(unameU(), []byte("synology")):
		return synology.Name
	case bytes.HasPrefix(unameO(), []byte("Tomato")):
		return tomato.Name
	case haveDir("/config/scripts/post-config.d"):
		return edgeos.Name
	case haveFile("/etc/ubnt/init/vyatta-router"):
		return edgeos.Name // For 2.x
	case isPfsense():
		return pfsense.Name
	case haveFile("/etc/firewalla_release"):
		return firewalla.Name
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

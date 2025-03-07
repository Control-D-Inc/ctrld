package router

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/certs"
	"github.com/Control-D-Inc/ctrld/internal/router/ddwrt"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/edgeos"
	"github.com/Control-D-Inc/ctrld/internal/router/firewalla"
	"github.com/Control-D-Inc/ctrld/internal/router/merlin"
	netgear "github.com/Control-D-Inc/ctrld/internal/router/netgear_orbi_voxel"
	"github.com/Control-D-Inc/ctrld/internal/router/openwrt"
	"github.com/Control-D-Inc/ctrld/internal/router/synology"
	"github.com/Control-D-Inc/ctrld/internal/router/tomato"
	"github.com/Control-D-Inc/ctrld/internal/router/ubios"
)

// Service is the interface to manage ctrld service on router.
type Service interface {
	// ConfigureService performs works for installing ctrla as a service on router.
	ConfigureService(*service.Config) error
	// Install performs necessary works after service.Install done.
	Install(*service.Config) error
	// Uninstall performs necessary works after service.Uninstallation done.
	Uninstall(*service.Config) error
}

// Router is the interface for managing ctrld running on router.
type Router interface {
	Service

	// PreRun performs works need to be done before ctrld being run on router.
	// Implementation should only return if the pre-condition was met (e.g: ntp synced).
	PreRun() error
	// Setup configures ctrld to be run on the router.
	Setup() error
	// Cleanup cleans up works setup on router by ctrld.
	Cleanup() error
}

// New returns new Router interface.
func New(cfg *ctrld.Config, cdMode bool) Router {
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
	case firewalla.Name:
		return firewalla.New(cfg)
	case netgear.Name:
		return netgear.New(cfg)
	}
	return newOsRouter(cfg, cdMode)
}

// IsNetGearOrbi reports whether the router is a Netgear Orbi router.
func IsNetGearOrbi() bool {
	return Name() == netgear.Name
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

// WaitProcessExited reports whether the "ctrld stop" command have to wait until ctrld process exited.
func WaitProcessExited() bool {
	return Name() == openwrt.Name
}

var routerPlatform atomic.Pointer[router]

type router struct {
	name string
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
	case ddwrt.Name, firewalla.Name, merlin.Name, netgear.Name, tomato.Name:
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.Dir(exe), nil
	case edgeos.Name:
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		// Using binary directory as home dir if it is located in /config.
		// Otherwise, fallback to old behavior for compatibility.
		if strings.HasPrefix(exe, "/config/") {
			return filepath.Dir(exe), nil
		}
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

// SelfInterfaces return list of *net.Interface that will be source of requests from router itself.
func SelfInterfaces() []*net.Interface {
	switch Name() {
	case firewalla.Name:
		return dnsmasq.FirewallaSelfInterfaces()
	default:
		return nil
	}
}

// LeaseFilesDir is the directory which contains lease files.
func LeaseFilesDir() string {
	if Name() == edgeos.Name {
		edgeos.LeaseFileDir()
	}
	return ""
}

// ServiceDependencies returns list of dependencies that ctrld services needs on this router.
// See https://pkg.go.dev/github.com/kardianos/service#Config for list format.
func ServiceDependencies() []string {
	if Name() == ubios.Name {
		// On Ubios, ctrld needs to start after unifi-mongodb,
		// so it can query custom client info mapping.
		return []string{
			"Wants=unifi-mongodb.service",
			"After=unifi-mongodb.service",
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
		if haveFile("/bin/config") { // TODO: is there any more reliable way?
			return netgear.Name
		}
		return openwrt.Name
	case isUbios():
		return ubios.Name
	case bytes.HasPrefix(unameU(), []byte("synology")):
		return synology.Name
	case bytes.HasPrefix(unameO(), []byte("Tomato")):
		return tomato.Name
	case haveDir("/config/scripts/post-config.d"):
		return edgeos.Name
	case haveFile("/etc/ubnt/init/vyatta-router"):
		return edgeos.Name // For 2.x
	case haveFile("/etc/firewalla_release"):
		return firewalla.Name
	}
	return osName
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

// isUbios reports whether the current machine is running on Ubios.
func isUbios() bool {
	if haveDir("/data/unifi") {
		return true
	}
	if err := exec.Command("ubnt-device-info", "firmware").Run(); err == nil {
		return true
	}
	return false
}

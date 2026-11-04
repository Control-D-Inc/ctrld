package cli

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The kernel gives an Ethernet-like link the type ARPHRD_ETHER.
const arphrdEther = 1

// Tests point the readers at a temporary directory.
var (
	sysfsNetRoot        = "/sys/class/net"
	sysfsVirtualNetRoot = "/sys/devices/virtual/net"
)

// noiseInterfacePrefixes name the interfaces of a container host. They change
// every few seconds, and no traffic of the host goes through them.
var noiseInterfacePrefixes = []string{"docker", "veth", "virbr", "br-"}

// usbTetherDrivers name the kernel modules of a phone that shares its data
// connection over the cable.
var usbTetherDrivers = []string{"ipheth", "rndis_host"}

// sysfsInfo holds what sysfs knows about one interface.
type sysfsInfo struct {
	Type     int
	DevType  string
	Driver   string
	Wireless bool
}

// patchNetIfaceName patches network interface names on Linux
// This is a no-op on Linux as interface names don't need special handling
func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

// validInterface reports whether the *net.Interface is a valid one.
// Only non-virtual interfaces are considered valid.
// This prevents DNS configuration on virtual interfaces like docker, veth, etc.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

// sysfsVirtualInterfaces returns the virtual interfaces of the host. The
// nameserver code has its own reader of the fixed path; this one reads the
// root that a test can point elsewhere.
func sysfsVirtualInterfaces() map[string]struct{} {
	s := make(map[string]struct{})
	entries, _ := os.ReadDir(sysfsVirtualNetRoot)
	for _, entry := range entries {
		if entry.IsDir() {
			s[strings.TrimSpace(entry.Name())] = struct{}{}
		}
	}
	return s
}

// sysfsInterfaceInfo reads the sysfs entry of an interface. A missing file
// leaves its field empty.
func sysfsInterfaceInfo(name string) sysfsInfo {
	dir := filepath.Join(sysfsNetRoot, name)
	info := sysfsInfo{DevType: sysfsUeventValue(dir, "DEVTYPE"), Driver: sysfsDriver(dir)}
	info.Type, _ = strconv.Atoi(readSysfsAttribute(dir, "type"))
	if entry, err := os.Stat(filepath.Join(dir, "wireless")); err == nil && entry.IsDir() {
		info.Wireless = true
	}
	return info
}

// readSysfsAttribute reads one attribute without its trailing newline.
func readSysfsAttribute(dir, file string) string {
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// sysfsUeventValue reads one entry of the uevent file.
func sysfsUeventValue(dir, key string) string {
	for _, line := range strings.Split(readSysfsAttribute(dir, "uevent"), "\n") {
		after, ok := strings.CutPrefix(strings.TrimSpace(line), key+"=")
		if !ok {
			continue
		}
		return strings.TrimSpace(after)
	}
	return ""
}

// sysfsDriver names the kernel module behind an interface. The driver link of
// the device points at the module, and the uevent of the device names it too.
func sysfsDriver(dir string) string {
	device := filepath.Join(dir, "device")
	if target, err := os.Readlink(filepath.Join(device, "driver")); err == nil {
		return filepath.Base(target)
	}
	if driver := sysfsUeventValue(device, "DRIVER"); driver != "" {
		return driver
	}
	return sysfsUeventValue(dir, "DRIVER")
}

// sysfsHardwarePort names the link in the words that the link type mapping
// reads. The port names of macOS use the same words.
func sysfsHardwarePort(info sysfsInfo) string {
	switch {
	case info.Wireless:
		return "Wi-Fi"
	case slices.Contains(usbTetherDrivers, info.Driver):
		return hardwarePortIPhoneUSB
	case info.DevType != "":
		return info.DevType
	case info.Type == arphrdEther:
		return "Ethernet"
	}
	return ""
}

// sysfsClass names the kind of an interface. The name rule comes before the
// device type, so an interface that went away keeps its class. A bridge, a
// bond, and a VLAN carry the traffic of the host, so they stay hardware.
func sysfsClass(name string, info sysfsInfo) string {
	switch {
	case info.DevType == "tun" || info.DevType == "tap":
		return "tunnel"
	case hasInterfacePrefix(name, noiseInterfacePrefixes...):
		return "virtual"
	case info.Wireless || info.Type == arphrdEther:
		return "hardware"
	}
	return ""
}

// platformInterfaceMeta returns the Linux class and link name of an interface.
// Linux has no service name.
func platformInterfaceMeta(name string) (class, hardwarePort, service string) {
	info := sysfsInterfaceInfo(name)
	return sysfsClass(name, info), sysfsHardwarePort(info), ""
}

// platformVirtualInterfaces returns the container interfaces of the host. The
// kernel lists the uplink bridges and the bonds beside them, and those carry
// the traffic of the host.
func platformVirtualInterfaces() map[string]struct{} {
	noise := make(map[string]struct{})
	for name := range sysfsVirtualInterfaces() {
		if hasInterfacePrefix(name, noiseInterfacePrefixes...) {
			noise[name] = struct{}{}
		}
	}
	return noise
}

// refreshInterfaceMeta does no work. Each sysfs read answers from the kernel
// of this moment, so there is no cache to refresh.
func refreshInterfaceMeta() {}

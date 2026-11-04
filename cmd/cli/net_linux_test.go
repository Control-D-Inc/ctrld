package cli

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// writeSysfsInterface builds one interface entry under a fake sysfs root.
func writeSysfsInterface(t *testing.T, root, name string, files map[string]string, wireless bool) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	for file, content := range files {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
	}
	if !wireless {
		return
	}
	if err := os.MkdirAll(filepath.Join(dir, "wireless"), 0o755); err != nil {
		t.Fatalf("create the wireless directory: %v", err)
	}
}

// writeSysfsDriverLink points the device entry of an interface at a driver.
func writeSysfsDriverLink(t *testing.T, root, name, driver string) {
	t.Helper()
	device := filepath.Join(root, name, "device")
	if err := os.MkdirAll(device, 0o755); err != nil {
		t.Fatalf("create %s: %v", device, err)
	}
	if err := os.Symlink(filepath.Join(root, "drivers", driver), filepath.Join(device, "driver")); err != nil {
		t.Fatalf("link the driver of %s: %v", name, err)
	}
}

// writeSysfsDriverUevent names the driver in the uevent of the device.
func writeSysfsDriverUevent(t *testing.T, root, name, driver string) {
	t.Helper()
	device := filepath.Join(root, name, "device")
	if err := os.MkdirAll(device, 0o755); err != nil {
		t.Fatalf("create %s: %v", device, err)
	}
	if err := os.WriteFile(filepath.Join(device, "uevent"), []byte("DRIVER="+driver+"\n"), 0o644); err != nil {
		t.Fatalf("write the uevent of %s: %v", name, err)
	}
}

// stubSysfsNetRoot points the sysfs reader at a temporary directory.
func stubSysfsNetRoot(t *testing.T) string {
	t.Helper()
	before := sysfsNetRoot
	t.Cleanup(func() { sysfsNetRoot = before })
	sysfsNetRoot = t.TempDir()
	return sysfsNetRoot
}

func Test_sysfsInterfaceInfo(t *testing.T) {
	root := stubSysfsNetRoot(t)
	writeSysfsInterface(t, root, "wlan0", map[string]string{
		"type":   "1\n",
		"uevent": "INTERFACE=wlan0\nDEVTYPE=wlan\nIFINDEX=3\n",
	}, true)
	writeSysfsInterface(t, root, "eth0", map[string]string{
		"type":   "1\n",
		"uevent": "INTERFACE=eth0\nIFINDEX=2\n",
	}, false)
	writeSysfsInterface(t, root, "tun0", map[string]string{
		"type":   "65534\n",
		"uevent": "DEVTYPE=tun\n",
	}, false)

	tests := []struct {
		name string
		want sysfsInfo
	}{
		{"wlan0", sysfsInfo{Type: 1, DevType: "wlan", Wireless: true}},
		{"eth0", sysfsInfo{Type: 1}},
		{"tun0", sysfsInfo{Type: 65534, DevType: "tun"}},
		{"absent0", sysfsInfo{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sysfsInterfaceInfo(tc.name); got != tc.want {
				t.Errorf("sysfsInterfaceInfo(%q) = %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}

func Test_sysfsClass(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		info  sysfsInfo
		want  string
	}{
		{"wireless", "wlan0", sysfsInfo{Wireless: true}, "hardware"},
		{"ethernet", "eth0", sysfsInfo{Type: 1}, "hardware"},
		{"tun devtype", "tun0", sysfsInfo{Type: 65534, DevType: "tun"}, "tunnel"},
		{"tap devtype", "tap0", sysfsInfo{Type: 1, DevType: "tap"}, "tunnel"},
		{"unknown", "sit0", sysfsInfo{Type: 65534}, ""},
		{"docker bridge", "docker0", sysfsInfo{Type: 1, DevType: "bridge"}, "virtual"},
		{"container link", "veth1a2b3c", sysfsInfo{Type: 1}, "virtual"},
		{"libvirt bridge", "virbr0", sysfsInfo{Type: 1, DevType: "bridge"}, "virtual"},
		{"compose bridge", "br-1a2b3c", sysfsInfo{Type: 1, DevType: "bridge"}, "virtual"},
		{"uplink bridge", "br0", sysfsInfo{Type: 1, DevType: "bridge"}, "hardware"},
		{"bond", "bond0", sysfsInfo{Type: 1, DevType: "bond"}, "hardware"},
		{"vlan uplink", "eth0.100", sysfsInfo{Type: 1, DevType: "vlan"}, "hardware"},
		{"removed container link", "veth9f8e7d", sysfsInfo{}, "virtual"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sysfsClass(tc.iface, tc.info); got != tc.want {
				t.Errorf("sysfsClass(%q, %+v) = %q, want %q", tc.iface, tc.info, got, tc.want)
			}
		})
	}
}

func Test_platformVirtualInterfaces_namesTheContainerInterfaces(t *testing.T) {
	root := t.TempDir()
	before := sysfsVirtualNetRoot
	t.Cleanup(func() { sysfsVirtualNetRoot = before })
	sysfsVirtualNetRoot = root
	for _, name := range []string{"lo", "docker0", "veth1a2b3c", "virbr0", "br-1a2b3c", "br0", "bond0"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	want := map[string]struct{}{"docker0": {}, "veth1a2b3c": {}, "virbr0": {}, "br-1a2b3c": {}}
	if got := platformVirtualInterfaces(); !maps.Equal(got, want) {
		t.Errorf("platformVirtualInterfaces = %v, want %v", got, want)
	}
	if got := sysfsVirtualInterfaces(); len(got) != 7 {
		t.Errorf("virtualInterfaces = %v, want every entry of the kernel directory", got)
	}
}

func Test_platformInterfaceMeta(t *testing.T) {
	root := stubSysfsNetRoot(t)
	writeSysfsInterface(t, root, "ctrld-test-eth0", map[string]string{
		"type":   "1\n",
		"uevent": "DEVTYPE=bridge\n",
	}, false)

	class, hardwarePort, service := platformInterfaceMeta("ctrld-test-eth0")
	if class != "hardware" {
		t.Errorf("class = %q, want hardware", class)
	}
	if hardwarePort != "bridge" {
		t.Errorf("hardware port = %q, want bridge", hardwarePort)
	}
	if service != "" {
		t.Errorf("service = %q, want empty", service)
	}
}

func Test_platformInterfaceMeta_namesTheLink(t *testing.T) {
	root := stubSysfsNetRoot(t)
	writeSysfsInterface(t, root, "wlan0", map[string]string{"type": "1\n", "uevent": "DEVTYPE=wlan\n"}, true)
	writeSysfsInterface(t, root, "eth0", map[string]string{"type": "1\n", "uevent": "INTERFACE=eth0\n"}, false)
	writeSysfsInterface(t, root, "br0", map[string]string{"type": "1\n", "uevent": "DEVTYPE=bridge\n"}, false)
	writeSysfsInterface(t, root, "tun0", map[string]string{"type": "65534\n", "uevent": "DEVTYPE=tun\n"}, false)
	writeSysfsInterface(t, root, "usb0", map[string]string{"type": "1\n"}, false)
	writeSysfsDriverLink(t, root, "usb0", "ipheth")
	writeSysfsInterface(t, root, "usb1", map[string]string{"type": "1\n"}, false)
	writeSysfsDriverUevent(t, root, "usb1", "rndis_host")
	writeSysfsInterface(t, root, "eth1", map[string]string{"type": "1\n"}, false)
	writeSysfsDriverUevent(t, root, "eth1", "e1000e")

	tests := []struct {
		iface, class, hardwarePort, linkType string
	}{
		{"wlan0", "hardware", "Wi-Fi", "wifi"},
		{"eth0", "hardware", "Ethernet", "ethernet"},
		{"eth1", "hardware", "Ethernet", "ethernet"},
		{"br0", "hardware", "bridge", "unknown"},
		{"tun0", "tunnel", "tun", "tunnel"},
		{"usb0", "hardware", hardwarePortIPhoneUSB, "usb_tether"},
		{"usb1", "hardware", hardwarePortIPhoneUSB, "usb_tether"},
	}
	for _, tc := range tests {
		t.Run(tc.iface, func(t *testing.T) {
			class, hardwarePort, service := platformInterfaceMeta(tc.iface)
			if class != tc.class || hardwarePort != tc.hardwarePort || service != "" {
				t.Errorf("platformInterfaceMeta(%q) = %q, %q, %q, want %q, %q, empty",
					tc.iface, class, hardwarePort, service, tc.class, tc.hardwarePort)
			}
			if got := linkTypeFor(hardwarePort, class); got != tc.linkType {
				t.Errorf("linkTypeFor(%q, %q) = %q, want %q", hardwarePort, class, got, tc.linkType)
			}
		})
	}
}

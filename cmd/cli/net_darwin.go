package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// hardwarePortInfo holds the two names that macOS gives a network device: the
// hardware port of the adapter and the network service that uses it.
type hardwarePortInfo struct {
	Port    string
	Service string
}

// A network event reads the ports of every interface, so the two networksetup
// calls run at most once per window.
const hardwarePortsTTL = time.Minute

// networksetupTimeout bounds one command. A stuck read must not hold the
// network callback that waits for the port names.
const networksetupTimeout = 5 * time.Second

// maxNetworksetupOutput bounds one read. A host with many ports stays far
// below it, so more than this is a broken command.
const maxNetworksetupOutput = 1 << 20

var errNetworksetupOutputTooLarge = errors.New("networksetup output above the bound")

var (
	hardwarePortsMu     sync.Mutex
	hardwarePortsCache  map[string]hardwarePortInfo
	hardwarePortsReadAt time.Time

	// Tests replace these seams to avoid a networksetup call.
	readHardwarePortsFn = readHardwarePorts
	hardwarePortsNowFn  = time.Now
)

func patchNetIfaceName(iface *net.Interface) (bool, error) {
	b, err := networksetupOutput("-listnetworkserviceorder")
	if err != nil {
		return false, err
	}

	patched := false
	if name := networkServiceName(iface.Name, bytes.NewReader(b)); name != "" {
		patched = true
		iface.Name = name
	}
	return patched, nil
}

func networkServiceName(ifaceName string, r io.Reader) string {
	return serviceNamesByDevice(r)[ifaceName]
}

// parseHardwarePorts maps each device of "networksetup -listallhardwareports"
// to its hardware port. Each block names the port before the device.
func parseHardwarePorts(r io.Reader) map[string]hardwarePortInfo {
	ports := make(map[string]hardwarePortInfo)
	scanner := scanNetworksetup(r)
	port := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, ok := strings.CutPrefix(line, "Hardware Port:"); ok {
			port = strings.TrimSpace(after)
			continue
		}
		after, ok := strings.CutPrefix(line, "Device:")
		if !ok {
			continue
		}
		device := strings.TrimSpace(after)
		if device == "" {
			continue
		}
		ports[device] = hardwarePortInfo{Port: port}
		port = ""
	}
	if scanner.Err() != nil {
		// A truncated read names fewer ports than the host has.
		return nil
	}
	return ports
}

// addServiceNames fills the service of every known device. A device that no
// hardware port lists is not a port of this host.
func addServiceNames(m map[string]hardwarePortInfo, r io.Reader) {
	for device, service := range serviceNamesByDevice(r) {
		info, known := m[device]
		if !known {
			continue
		}
		info.Service = service
		m[device] = info
	}
}

// hardwarePortsByDevice returns the port and service of every device. The
// commands run outside the mutex, so a slow read blocks no other caller.
func hardwarePortsByDevice() map[string]hardwarePortInfo {
	if ports, fresh := cachedHardwarePorts(); fresh {
		return ports
	}
	return storeHardwarePorts(readHardwarePortsFn())
}

// cachedHardwarePorts reports whether the read window still holds.
func cachedHardwarePorts() (map[string]hardwarePortInfo, bool) {
	hardwarePortsMu.Lock()
	defer hardwarePortsMu.Unlock()
	if hardwarePortsReadAt.IsZero() {
		return nil, false
	}
	return hardwarePortsCache, hardwarePortsNowFn().Sub(hardwarePortsReadAt) < hardwarePortsTTL
}

// storeHardwarePorts starts the window again and keeps the last good map. A
// failing command must run once per window, not once per lookup.
func storeHardwarePorts(ports map[string]hardwarePortInfo) map[string]hardwarePortInfo {
	hardwarePortsMu.Lock()
	defer hardwarePortsMu.Unlock()
	hardwarePortsReadAt = hardwarePortsNowFn()
	if ports != nil {
		hardwarePortsCache = ports
	}
	return hardwarePortsCache
}

// readHardwarePorts runs the two networksetup commands.
func readHardwarePorts() map[string]hardwarePortInfo {
	b, err := networksetupOutput("-listallhardwareports")
	if err != nil {
		return nil
	}
	ports := parseHardwarePorts(bytes.NewReader(b))
	if ports == nil {
		// A truncated list must keep the last good map.
		return nil
	}
	b, err = networksetupOutput("-listnetworkserviceorder")
	if err != nil {
		return ports
	}
	addServiceNames(ports, bytes.NewReader(b))
	return ports
}

// networksetupOutput runs one networksetup list under a time bound and a size
// bound.
func networksetupOutput(arg string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), networksetupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "networksetup", arg)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := readBoundedOutput(stdout)
	if readErr != nil {
		// A command ends only when something reads the rest of its output.
		_, _ = io.Copy(io.Discard, stdout)
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return out, readErr
}

// readBoundedOutput reads at most maxNetworksetupOutput bytes and reports an
// error above that.
func readBoundedOutput(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxNetworksetupOutput+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxNetworksetupOutput {
		return nil, errNetworksetupOutputTooLarge
	}
	return out, nil
}

// platformInterfaceMeta returns the macOS names of an interface. The class
// comes from the interface name, so it stays empty here.
func platformInterfaceMeta(name string) (class, hardwarePort, service string) {
	info := hardwarePortsByDevice()[name]
	return "", info.Port, info.Service
}

// platformVirtualInterfaces returns no set. The name rules already class the
// AirDrop and the link-local interfaces of macOS.
func platformVirtualInterfaces() map[string]struct{} {
	return nil
}

// refreshInterfaceMeta drops the read window. The cache has no port name for
// an adapter that appeared, so the next lookup reads the ports again.
func refreshInterfaceMeta() {
	hardwarePortsMu.Lock()
	defer hardwarePortsMu.Unlock()
	hardwarePortsReadAt = time.Time{}
}

// validInterface reports whether the *net.Interface is a valid one.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

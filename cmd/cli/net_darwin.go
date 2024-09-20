package cli

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os/exec"
	"strings"
)

func patchNetIfaceName(iface *net.Interface) error {
	b, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return err
	}

	if name := networkServiceName(iface.Name, bytes.NewReader(b)); name != "" {
		iface.Name = name
		mainLog.Load().Debug().Str("network_service", name).Msg("found network service name for interface")
	}
	return nil
}

func networkServiceName(ifaceName string, r io.Reader) string {
	scanner := bufio.NewScanner(r)
	prevLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "*") {
			// Network services is disabled.
			continue
		}
		if !strings.Contains(line, "Device: "+ifaceName) {
			prevLine = line
			continue
		}
		parts := strings.SplitN(prevLine, " ", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// validInterface reports whether the *net.Interface is a valid one.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

// validInterfacesMap returns a set of all valid hardware ports.
func validInterfacesMap() map[string]struct{} {
	b, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil
	}
	return parseListAllHardwarePorts(bytes.NewReader(b))
}

// parseListAllHardwarePorts parses output of "networksetup -listallhardwareports"
// and returns map presents all hardware ports.
func parseListAllHardwarePorts(r io.Reader) map[string]struct{} {
	m := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		after, ok := strings.CutPrefix(line, "Device: ")
		if !ok {
			continue
		}
		m[after] = struct{}{}
	}
	return m
}

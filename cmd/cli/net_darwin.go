package cli

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os/exec"
	"strings"
)

func patchNetIfaceName(iface *net.Interface) (bool, error) {
	b, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
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

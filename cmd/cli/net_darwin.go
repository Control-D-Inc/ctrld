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

// validInterface reports whether the *net.Interface is a valid one, which includes:
//
// - en0: physical wireless
// - en1: Thunderbolt 1
// - en2: Thunderbolt 2
// - en3: Thunderbolt 3
// - en4: Thunderbolt 4
//
// For full list, see: https://unix.stackexchange.com/questions/603506/what-are-these-ifconfig-interfaces-on-macos
func validInterface(iface *net.Interface) bool {
	switch iface.Name {
	case "en0", "en1", "en2", "en3", "en4":
		return true
	default:
		return false
	}
}

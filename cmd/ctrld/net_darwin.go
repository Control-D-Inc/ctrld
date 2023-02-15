package main

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
		mainLog.Debug().Str("network_service", name).Msg("found network service name for interface")
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

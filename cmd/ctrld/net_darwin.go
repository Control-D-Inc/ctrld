package main

import (
	"bufio"
	"bytes"
	"net"
	"os/exec"
	"strings"
)

func patchNetIfaceName(iface *net.Interface) error {
	b, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "*") {
			// Network services is disabled.
			continue
		}
		if !strings.Contains(line, "Device: "+iface.Name) {
			continue
		}
		parts := strings.Split(line, ",")
		if _, networkServiceName, ok := strings.Cut(parts[0], "(Hardware Port: "); ok {
			mainLog.Debug().Str("network_service", networkServiceName).Msg("found network service name for interface")
			iface.Name = networkServiceName
		}
	}
	return nil
}

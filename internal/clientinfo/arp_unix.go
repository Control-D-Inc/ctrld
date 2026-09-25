//go:build !linux && !windows

package clientinfo

import (
	"os/exec"
	"strings"
)

func (a *arpDiscover) scan() {
	data, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) <= 3 {
			continue
		}

		// trim brackets
		// Unix "arp -an" output formats IP addresses with parentheses like "(192.168.1.1)"
		// We need to remove these brackets for proper IP parsing
		ip := strings.ReplaceAll(fields[1], "(", "")
		ip = strings.ReplaceAll(ip, ")", "")

		mac := fields[3]
		a.mac.Store(ip, mac)
		a.ip.Store(mac, ip)
	}
}

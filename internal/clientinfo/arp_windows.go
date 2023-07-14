package clientinfo

import (
	"os/exec"
	"strings"
)

func (a *arpDiscover) scan() {
	data, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return
	}

	header := false
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) == 0 {
			continue // empty lines
		}
		if line[0] != ' ' {
			header = true // "Interface:" lines, next is header line.
			continue
		}
		if header {
			header = false // header lines
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		mac := strings.ReplaceAll(fields[1], "-", ":")
		a.mac.Store(ip, mac)
		a.ip.Store(mac, ip)
	}
}

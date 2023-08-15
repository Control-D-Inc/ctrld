package clientinfo

import (
	"bufio"
	"os"
	"strings"
)

const procNetArpFile = "/proc/net/arp"

func (a *arpDiscover) scan() {
	f, err := os.Open(procNetArpFile)
	if err != nil {
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan() // skip header
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		ip := fields[0]
		mac := fields[3]
		a.mac.Store(ip, mac)
		a.ip.Store(mac, ip)
	}
}

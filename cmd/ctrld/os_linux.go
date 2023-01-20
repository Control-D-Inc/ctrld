package main

import (
	"bufio"
	"bytes"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// allocate loopback ip
// sudo ip a add 127.0.0.2/24 dev lo
func allocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "add", ip+"/24", "dev", "lo")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "del", ip+"/24", "dev", "lo")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}

// set the dns server for the provided network interface
func setDNS(iface *net.Interface, nameservers []string) error {
	logf := func(format string, args ...any) {
		mainLog.Debug().Msgf(format, args...)
	}

	r, err := dns.NewOSConfigurator(logf, iface.Name)
	if err != nil {
		mainLog.Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}
	defer r.Close()
	ns := make([]netip.Addr, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, netip.MustParseAddr(nameserver))
	}
	return r.SetDNS(dns.OSConfig{
		Nameservers:   ns,
		SearchDomains: []dnsname.FQDN{},
	})
}

func resetDNS(iface *net.Interface) error {
	c := client4.NewClient()
	conversation, err := c.Exchange(iface.Name)
	if err != nil {
		return err
	}
	for _, packet := range conversation {
		if packet.MessageType() == dhcpv4.MessageTypeAck {
			nameservers := packet.DNS()
			ns := make([]string, 0, len(nameservers))
			for _, nameserver := range nameservers {
				ns = append(ns, nameserver.String())
			}
			_ = setDNS(iface, ns)
		}
	}

	if supportsIPv6() {
		c := client6.NewClient()
		conversation, err := c.Exchange(iface.Name)
		if err != nil {
			return err
		}
		for _, packet := range conversation {
			if packet.Type() == dhcpv6.MessageTypeReply {
				msg, err := packet.GetInnerMessage()
				if err != nil {
					return err
				}
				nameservers := msg.Options.DNS()
				ns := make([]string, 0, len(nameservers))
				for _, nameserver := range nameservers {
					ns = append(ns, nameserver.String())
				}
				_ = setDNS(iface, ns)
			}
		}
	}
	return nil
}

func currentDNS(iface *net.Interface) []string {
	for _, fn := range []getDNS{getDNSByResolvectl, getDNSByNmcli, resolvconffile.NameServers} {
		if ns := fn(iface.Name); len(ns) > 0 {
			return ns
		}
	}
	return nil
}

func getDNSByResolvectl(iface string) []string {
	b, err := exec.Command("resolvectl", "dns", "-i", iface).Output()
	if err != nil {
		return nil
	}

	parts := strings.Fields(strings.SplitN(string(b), "%", 2)[0])
	if len(parts) > 2 {
		return parts[3:]
	}
	return nil
}

func getDNSByNmcli(iface string) []string {
	b, err := exec.Command("nmcli", "dev", "show", iface).Output()
	if err != nil {
		return nil
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	var dns []string
	do := func(line string) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) > 1 {
			dns = append(dns, strings.TrimSpace(parts[1]))
		}
	}
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.HasPrefix(line, "IP4.DNS"):
			fallthrough
		case strings.HasPrefix(line, "IP6.DNS"):
			do(line)
		}
	}
	return dns
}

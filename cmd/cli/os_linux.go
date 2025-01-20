package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld/internal/dns"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

const resolvConfBackupFailedMsg = "open /etc/resolv.pre-ctrld-backup.conf: read-only file system"

// allocate loopback ip
// sudo ip a add 127.0.0.2/24 dev lo
func allocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "add", ip+"/24", "dev", "lo")
	if out, err := cmd.CombinedOutput(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("allocateIP failed: %s", string(out))
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ip", "a", "del", ip+"/24", "dev", "lo")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}

const maxSetDNSAttempts = 5

// setDnsIgnoreUnusableInterface likes setDNS, but return a nil error if the interface is not usable.
func setDnsIgnoreUnusableInterface(iface *net.Interface, nameservers []string) error {
	return setDNS(iface, nameservers)
}

func setDNS(iface *net.Interface, nameservers []string) error {
	r, err := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}

	ns := make([]netip.Addr, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, netip.MustParseAddr(nameserver))
	}

	osConfig := dns.OSConfig{
		Nameservers:   ns,
		SearchDomains: []dnsname.FQDN{},
	}
	trySystemdResolve := false
	for i := 0; i < maxSetDNSAttempts; i++ {
		if err := r.SetDNS(osConfig); err != nil {
			if strings.Contains(err.Error(), "Rejected send message") &&
				strings.Contains(err.Error(), "org.freedesktop.network1.Manager") {
				mainLog.Load().Warn().Msg("Interfaces are managed by systemd-networkd, switch to systemd-resolve for setting DNS")
				trySystemdResolve = true
				break
			}
			// This error happens on read-only file system, which causes ctrld failed to create backup
			// for /etc/resolv.conf file. It is ok, because the DNS is still set anyway, and restore
			// DNS will fallback to use DHCP if there's no backup /etc/resolv.conf file.
			// The error format is controlled by us, so checking for error string is fine.
			// See: ../../internal/dns/direct.go:L278
			if r.Mode() == "direct" && strings.Contains(err.Error(), resolvConfBackupFailedMsg) {
				return nil
			}
			return err
		}
		if useSystemdResolved {
			if out, err := exec.Command("systemctl", "restart", "systemd-resolved").CombinedOutput(); err != nil {
				mainLog.Load().Warn().Err(err).Msgf("could not restart systemd-resolved: %s", string(out))
			}
		}
		currentNS := currentDNS(iface)
		if isSubSet(nameservers, currentNS) {
			return nil
		}
	}
	if trySystemdResolve {
		// Stop systemd-networkd and retry setting DNS.
		if out, err := exec.Command("systemctl", "stop", "systemd-networkd").CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w", string(out), err)
		}
		args := []string{"--interface=" + iface.Name, "--set-domain=~"}
		for _, nameserver := range nameservers {
			args = append(args, "--set-dns="+nameserver)
		}
		for i := 0; i < maxSetDNSAttempts; i++ {
			if out, err := exec.Command("systemd-resolve", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %w", string(out), err)
			}
			currentNS := currentDNS(iface)
			if isSubSet(nameservers, currentNS) {
				return nil
			}
			time.Sleep(time.Second)
		}
	}
	mainLog.Load().Debug().Msg("DNS was not set for some reason")
	return nil
}

// resetDnsIgnoreUnusableInterface likes resetDNS, but return a nil error if the interface is not usable.
func resetDnsIgnoreUnusableInterface(iface *net.Interface) error {
	return resetDNS(iface)
}

func resetDNS(iface *net.Interface) (err error) {
	defer func() {
		if err == nil {
			return
		}
		// Start systemd-networkd if present.
		if exe, _ := exec.LookPath("/lib/systemd/systemd-networkd"); exe != "" {
			_ = exec.Command("systemctl", "start", "systemd-networkd").Run()
		}
		if r, oerr := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name); oerr == nil {
			_ = r.SetDNS(dns.OSConfig{})
			if err := r.Close(); err != nil {
				mainLog.Load().Error().Err(err).Msg("failed to rollback DNS setting")
				return
			}
			err = nil
		}
	}()

	var ns []string
	c, err := nclient4.New(iface.Name)
	if err != nil {
		return fmt.Errorf("nclient4.New: %w", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	lease, err := c.Request(ctx)
	if err != nil {
		return fmt.Errorf("nclient4.Request: %w", err)
	}
	for _, nameserver := range lease.ACK.DNS() {
		if nameserver.Equal(net.IPv4zero) {
			continue
		}
		ns = append(ns, nameserver.String())
	}

	// TODO(cuonglm): handle DHCPv6 properly.
	if ctrldnet.IPv6Available(ctx) {
		c := client6.NewClient()
		conversation, err := c.Exchange(iface.Name)
		if err != nil && !errAddrInUse(err) {
			mainLog.Load().Debug().Err(err).Msg("could not exchange DHCPv6")
		}
		for _, packet := range conversation {
			if packet.Type() == dhcpv6.MessageTypeReply {
				msg, err := packet.GetInnerMessage()
				if err != nil {
					mainLog.Load().Debug().Err(err).Msg("could not get inner DHCPv6 message")
					return nil
				}
				nameservers := msg.Options.DNS()
				for _, nameserver := range nameservers {
					ns = append(ns, nameserver.String())
				}
			}
		}
	}

	return ignoringEINTR(func() error {
		return setDNS(iface, ns)
	})
}

// restoreDNS restores the DNS settings of the given interface.
// this should only be executed upon turning off the ctrld service.
func restoreDNS(iface *net.Interface) (err error) {
	return err
}

func currentDNS(iface *net.Interface) []string {
	for _, fn := range []getDNS{getDNSByResolvectl, getDNSBySystemdResolved, getDNSByNmcli, resolvconffile.NameServers} {
		if ns := fn(iface.Name); len(ns) > 0 {
			return ns
		}
	}
	return nil
}

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	return currentDNS(iface), nil
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

func getDNSBySystemdResolved(iface string) []string {
	b, err := exec.Command("systemd-resolve", "--status", iface).Output()
	if err != nil {
		return nil
	}
	return getDNSBySystemdResolvedFromReader(bytes.NewReader(b))
}

func getDNSBySystemdResolvedFromReader(r io.Reader) []string {
	scanner := bufio.NewScanner(r)
	var ret []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(ret) > 0 {
			if net.ParseIP(line) != nil {
				ret = append(ret, line)
			}
			continue
		}
		after, found := strings.CutPrefix(line, "DNS Servers: ")
		if !found {
			continue
		}
		if net.ParseIP(after) != nil {
			ret = append(ret, after)
		}
	}
	return ret
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

func ignoringEINTR(fn func() error) error {
	for {
		err := fn()
		if err != syscall.EINTR {
			return err
		}
	}
}

// isSubSet reports whether s2 contains all elements of s1.
func isSubSet(s1, s2 []string) bool {
	ok := true
	for _, ns := range s1 {
		if slices.Contains(s2, ns) {
			continue
		}
		ok = false
		break
	}
	return ok
}

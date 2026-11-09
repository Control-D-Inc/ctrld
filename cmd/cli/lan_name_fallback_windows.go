//go:build windows

package cli

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	nbnsPort = 137
	mdnsPort = 5353
)

var mdnsGroup = netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), mdnsPort)

// newPlatformLanNameFallback wires the LAN name fallback to the Windows
// adapters and DNS Client settings. See lan_name_fallback.go.
func newPlatformLanNameFallback() *lanNameFallback {
	return newLanNameFallback(lanFallbackPlatform{
		adapters:    windowsLanFallbackAdapters,
		mdnsEnabled: windowsMDNSEnabled,
		nbns:        windowsNBNSQuery,
		mdns:        windowsMDNSQuery,
	})
}

// windowsLanFallbackAdapters lists the up IPv4 adapters with a real subnet.
// NetBIOS follows each adapter's effective NetBIOS over TCP/IP state, which
// already resolves the "use the DHCP setting" default, so an adapter where an
// administrator or DHCP turned NetBIOS off is never broadcast on.
func windowsLanFallbackAdapters() []lanFallbackAdapter {
	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_INET, winipcfg.GAAFlagIncludePrefix)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("lan name fallback: could not list adapters")
		return nil
	}
	global := windowsGlobalDNSSuffixes()
	var out []lanFallbackAdapter
	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp || aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		var prefix netip.Prefix
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip, ok := netip.AddrFromSlice(ua.Address.IP())
			if !ok || !ip.Unmap().Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			bits := int(ua.OnLinkPrefixLength)
			// A /31 or /32 (point-to-point, most VPN tunnels) has no LAN to
			// broadcast to.
			if bits < 8 || bits > 30 {
				continue
			}
			prefix = netip.PrefixFrom(ip.Unmap(), bits)
			break
		}
		if !prefix.IsValid() {
			continue
		}
		a := lanFallbackAdapter{
			ifIndex:   int(aa.IfIndex),
			prefix:    prefix,
			netbios:   aa.Flags&winipcfg.IPAAFlagNetbiosOverTcpipEnabled != 0,
			multicast: aa.Flags&winipcfg.IPAAFlagNoMulticast == 0,
		}
		addSuffix := func(s string) {
			s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
			if s == "" {
				return
			}
			for _, have := range a.suffixes {
				if have == s {
					return
				}
			}
			a.suffixes = append(a.suffixes, s)
		}
		addSuffix(aa.DNSSuffix())
		for sd := aa.FirstDNSSuffix; sd != nil; sd = sd.Next {
			addSuffix(sd.String())
		}
		for _, s := range global {
			addSuffix(s)
		}
		out = append(out, a)
	}
	return out
}

// windowsGlobalDNSSuffixes returns the primary DNS suffix and the global
// suffix search list, which the DNS Client also appends to single labels.
func windowsGlobalDNSSuffixes() []string {
	var out []string
	for _, path := range []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		for _, name := range []string{"Domain", "NV Domain", "PrimaryDnsSuffix"} {
			if v, _, err := k.GetStringValue(name); err == nil && v != "" {
				out = append(out, v)
			}
		}
		if v, _, err := k.GetStringValue("SearchList"); err == nil {
			out = append(out, strings.Split(v, ",")...)
		}
		k.Close()
	}
	return out
}

// windowsMDNSEnabled reports whether the DNS Client would use mDNS. Any of the
// documented off switches turns ctrld's mDNS fallback off too: the local
// EnableMDNS value, and the Group Policy multicast switches. The policy
// "Turn off multicast name resolution" is documented for LLMNR; treating it
// as an mDNS opt-out as well errs on the side of the administrator.
func windowsMDNSEnabled() bool {
	off := func(path, name string) bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		defer k.Close()
		v, _, err := k.GetIntegerValue(name)
		return err == nil && v == 0
	}
	switch {
	case off(`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, "EnableMDNS"),
		off(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMDNS"),
		off(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast"):
		return false
	}
	return true
}

// lanFallbackConn opens an ephemeral UDP socket on the adapter's own address,
// so the query leaves on that adapter with its source address, as Windows'
// own NetBIOS and mDNS queries do.
func lanFallbackConn(ctx context.Context, a lanFallbackAdapter) (net.PacketConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp4", netip.AddrPortFrom(a.prefix.Addr(), 0).String())
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	return pc, nil
}

func windowsNBNSQuery(ctx context.Context, a lanFallbackAdapter, name string) (netip.Addr, error) {
	pc, err := lanFallbackConn(ctx, a)
	if err != nil {
		return netip.Addr{}, err
	}
	defer pc.Close()
	return nbnsExchange(ctx, pc, netip.AddrPortFrom(a.broadcast(), nbnsPort), name, a.onLink)
}

func windowsMDNSQuery(ctx context.Context, a lanFallbackAdapter, name string) (netip.Addr, error) {
	pc, err := lanFallbackConn(ctx, a)
	if err != nil {
		return netip.Addr{}, err
	}
	defer pc.Close()
	// Multicast leaves on the route table's interface unless told otherwise.
	if ifi, err := net.InterfaceByIndex(a.ifIndex); err == nil {
		p4 := ipv4.NewPacketConn(pc)
		_ = p4.SetMulticastInterface(ifi)
		_ = p4.SetMulticastTTL(255)
	}
	return mdnsExchange(ctx, pc, mdnsGroup, name, a.onLink)
}

package clientinfo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/Control-D-Inc/ctrld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// ndpDiscover provides client discovery functionality using NDP protocol.
type ndpDiscover struct {
	mac    sync.Map // ip  => mac
	ip     sync.Map // mac => ip
	logger *ctrld.Logger
}

// refresh re-scans the NDP table.
func (nd *ndpDiscover) refresh() error {
	nd.scan()
	return nil
}

// LookupIP returns the ipv6 associated with the input MAC address.
func (nd *ndpDiscover) LookupIP(mac string) string {
	val, ok := nd.ip.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

// LookupMac returns the MAC address of the given IP address.
func (nd *ndpDiscover) LookupMac(ip string) string {
	val, ok := nd.mac.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

// String returns human-readable format of ndpDiscover.
func (nd *ndpDiscover) String() string {
	return "ndp"
}

// List returns all known IP addresses.
func (nd *ndpDiscover) List() []string {
	if nd == nil {
		return nil
	}
	var ips []string
	nd.ip.Range(func(key, value any) bool {
		ips = append(ips, value.(string))
		return true
	})
	nd.mac.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

// saveInfo saves ip and mac info to mapping table.
func (nd *ndpDiscover) saveInfo(ip, mac string) {
	ip = normalizeIP(ip)
	// Store ip => map mapping,
	nd.mac.Store(ip, mac)

	// Do not store mac => ip mapping if new ip is a link local unicast.
	if ctrldnet.IsLinkLocalUnicastIPv6(ip) {
		return
	}

	// If there is old ip => mac mapping, delete it.
	if old, existed := nd.ip.Load(mac); existed {
		oldIP := old.(string)
		if oldIP != ip {
			nd.mac.Delete(oldIP)
		}
	}
	// Store mac => ip mapping.
	nd.ip.Store(mac, ip)
}

// listen listens on ipv6 link local for Neighbor Solicitation message
// to update new neighbors information to ndp table.
func (nd *ndpDiscover) listen(ctx context.Context) {
	ifis, err := allInterfacesWithV6LinkLocal()
	if err != nil {
		nd.logger.Debug().Err(err).Msg("failed to find valid ipv6 interfaces")
		return
	}
	for _, ifi := range ifis {
		go func(ifi *net.Interface) {
			nd.listenOnInterface(ctx, ifi)
		}(ifi)
	}
}

func (nd *ndpDiscover) listenOnInterface(ctx context.Context, ifi *net.Interface) {
	c, ip, err := ndp.Listen(ifi, ndp.Unspecified)
	if err != nil {
		nd.logger.Debug().Err(err).Msg("ndp listen failed")
		return
	}
	defer c.Close()
	nd.logger.Debug().Msgf("listening ndp on: %s", ip.String())
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		msg, _, from, readErr := c.ReadFrom()
		if readErr != nil {
			var opErr *net.OpError
			if errors.As(readErr, &opErr) && (opErr.Timeout() || opErr.Temporary()) {
				continue
			}
			nd.logger.Debug().Err(readErr).Msg("ndp read loop error")
			return
		}

		// Only looks for neighbor solicitation message, since new clients
		// which join network will broadcast this message to us.
		am, ok := msg.(*ndp.NeighborSolicitation)
		if !ok {
			continue
		}
		fromIP := from.String()
		for _, opt := range am.Options {
			if lla, ok := opt.(*ndp.LinkLayerAddress); ok {
				mac := lla.Addr.String()
				nd.saveInfo(fromIP, mac)
			}
		}
	}
}

// scanWindows populates NDP table using information from "netsh" command.
func (nd *ndpDiscover) scanWindows(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if mac := parseMAC(fields[1]); mac != "" {
			nd.saveInfo(fields[0], mac)
		}
	}
}

// scanUnix populates NDP table using information from "ndp" command.
func (nd *ndpDiscover) scanUnix(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if mac := parseMAC(fields[1]); mac != "" {
			ip := fields[0]
			if idx := strings.IndexByte(ip, '%'); idx != -1 {
				ip = ip[:idx]
			}
			nd.saveInfo(ip, mac)
		}
	}
}

// normalizeMac ensure the given MAC address have the proper format
// before being parsed.
//
// Example, changing "00:0:00:0:00:01" to "00:00:00:00:00:01", which
// can be seen on Darwin.
func normalizeMac(mac string) string {
	if len(mac) == 17 {
		return mac
	}
	// Windows use "-" instead of ":" as separator.
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, c := range parts {
		if len(c) == 1 {
			parts[i] = "0" + c
		}
	}
	return strings.Join(parts, ":")
}

// parseMAC parses the input MAC, doing normalization,
// and return the result after calling net.ParseMac function.
func parseMAC(mac string) string {
	hw, _ := net.ParseMAC(normalizeMac(mac))
	return hw.String()
}

// allInterfacesWithV6LinkLocal returns all interfaces which is capable of using NDP.
func allInterfacesWithV6LinkLocal() ([]*net.Interface, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res := make([]*net.Interface, 0, len(ifis))
	for _, ifi := range ifis {
		ifi := ifi
		// Skip if iface is down/loopback/non-multicast.
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				return nil, fmt.Errorf("invalid ip address: %s", ipNet.String())
			}
			if ip.Is6() && !ip.Is4In6() {
				res = append(res, &ifi)
				break
			}
		}
	}
	return res, nil
}

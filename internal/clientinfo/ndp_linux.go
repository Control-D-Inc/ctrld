package clientinfo

import (
	"context"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Control-D-Inc/ctrld"
)

// scan populates NDP table using information from system mappings.
func (nd *ndpDiscover) scan() {
	neighs, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		ctrld.ProxyLogger.Load().Warn().Err(err).Msg("could not get neigh list")
		return
	}

	for _, n := range neighs {
		// Skipping non-reachable neighbors.
		if n.State&netlink.NUD_REACHABLE == 0 {
			continue
		}
		ip := n.IP.String()
		mac := n.HardwareAddr.String()
		nd.saveInfo(ip, mac)
	}
}

// subscribe watches NDP table changes and update new information to local table.
func (nd *ndpDiscover) subscribe(ctx context.Context) {
	ch := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.NeighSubscribe(ch, done); err != nil {
		ctrld.ProxyLogger.Load().Err(err).Msg("could not perform neighbor subscribing")
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case nu := <-ch:
			if nu.Family != netlink.FAMILY_V6 {
				continue
			}
			ip := normalizeIP(nu.IP.String())
			if nu.Type == unix.RTM_DELNEIGH {
				ctrld.ProxyLogger.Load().Debug().Msgf("removing NDP neighbor: %s", ip)
				nd.mac.Delete(ip)
				continue
			}
			mac := nu.HardwareAddr.String()
			switch nu.State {
			case netlink.NUD_REACHABLE:
				nd.saveInfo(ip, mac)
			case netlink.NUD_FAILED:
				ctrld.ProxyLogger.Load().Debug().Msgf("removing NDP neighbor with failed state: %s", ip)
				nd.mac.Delete(ip)
			}
		}
	}
}

package clientinfo

import (
	"github.com/vishvananda/netlink"

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

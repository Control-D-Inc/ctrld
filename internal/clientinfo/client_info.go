package clientinfo

import (
	"strings"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// IpResolver is the interface for retrieving IP from Mac.
type IpResolver interface {
	LookupIP(mac string) string
}

// MacResolver is the interface for retrieving Mac from IP.
type MacResolver interface {
	LookupMac(ip string) string
}

// HostnameByIpResolver is the interface for retrieving hostname from IP.
type HostnameByIpResolver interface {
	LookupHostnameByIP(ip string) string
}

// HostnameByMacResolver is the interface for retrieving hostname from Mac.
type HostnameByMacResolver interface {
	LookupHostnameByMac(mac string) string
}

type HostnameResolver interface {
	HostnameByIpResolver
	HostnameByMacResolver
}

type refresher interface {
	refresh() error
}

type Table struct {
	ipResolvers       []IpResolver
	macResolvers      []MacResolver
	hostnameResolvers []HostnameResolver
	refreshers        []refresher

	dhcp   *dhcp
	merlin *merlinDiscover
	arp    *arpDiscover
	ptr    *ptrDiscover
	mdns   *mdns
	cfg    *ctrld.Config
	quitCh chan struct{}
	selfIP string
}

func NewTable(cfg *ctrld.Config, selfIP string) *Table {
	return &Table{
		cfg:    cfg,
		quitCh: make(chan struct{}),
		selfIP: selfIP,
	}
}

func (t *Table) AddLeaseFile(name string, format ctrld.LeaseFileFormat) {
	if !t.discoverDHCP() {
		return
	}
	clientInfoFiles[name] = format
}

func (t *Table) RefreshLoop(stopCh chan struct{}) {
	timer := time.NewTicker(time.Minute * 5)
	for {
		select {
		case <-timer.C:
			for _, r := range t.refreshers {
				_ = r.refresh()
			}
		case <-stopCh:
			close(t.quitCh)
			return
		}
	}
}

func (t *Table) Init() {
	if t.discoverDHCP() || t.discoverARP() {
		t.merlin = &merlinDiscover{}
		if err := t.merlin.refresh(); err != nil {
			ctrld.ProxyLog.Error().Err(err).Msg("could not init Merlin discover")
		} else {
			t.hostnameResolvers = append(t.hostnameResolvers, t.merlin)
			t.refreshers = append(t.refreshers, t.merlin)
		}
	}
	if t.discoverDHCP() {
		t.dhcp = &dhcp{selfIP: t.selfIP}
		ctrld.ProxyLog.Debug().Msg("start dhcp discovery")
		if err := t.dhcp.refresh(); err != nil {
			ctrld.ProxyLog.Error().Err(err).Msg("could not init DHCP discover")
		} else {
			t.ipResolvers = append(t.ipResolvers, t.dhcp)
			t.macResolvers = append(t.macResolvers, t.dhcp)
			t.hostnameResolvers = append(t.hostnameResolvers, t.dhcp)
			t.refreshers = append(t.refreshers, t.dhcp)
		}
		go t.dhcp.watchChanges()
	}
	if t.discoverARP() {
		t.arp = &arpDiscover{}
		ctrld.ProxyLog.Debug().Msg("start arp discovery")
		if err := t.arp.refresh(); err != nil {
			ctrld.ProxyLog.Error().Err(err).Msg("could not init ARP discover")
		} else {
			t.ipResolvers = append(t.ipResolvers, t.arp)
			t.macResolvers = append(t.macResolvers, t.arp)
			t.refreshers = append(t.refreshers, t.arp)
		}
	}
	if t.discoverPTR() {
		t.ptr = &ptrDiscover{resolver: ctrld.NewPrivateResolver()}
		ctrld.ProxyLog.Debug().Msg("start ptr discovery")
		if err := t.ptr.refresh(); err != nil {
			ctrld.ProxyLog.Error().Err(err).Msg("could not init PTR discover")
		} else {
			t.hostnameResolvers = append(t.hostnameResolvers, t.ptr)
			t.refreshers = append(t.refreshers, t.ptr)
		}
	}
	if t.discoverMDNS() {
		t.mdns = &mdns{}
		ctrld.ProxyLog.Debug().Msg("start mdns discovery")
		if err := t.mdns.init(t.quitCh); err != nil {
			ctrld.ProxyLog.Error().Err(err).Msg("could not init mDNS discover")
		} else {
			t.hostnameResolvers = append(t.hostnameResolvers, t.mdns)
		}
	}
}

func (t *Table) LookupIP(mac string) string {
	for _, r := range t.ipResolvers {
		if ip := r.LookupIP(mac); ip != "" {
			return ip
		}
	}
	return ""
}

func (t *Table) LookupMac(ip string) string {
	t.arp.mac.Range(func(key, value any) bool {
		return true
	})
	for _, r := range t.macResolvers {
		if mac := r.LookupMac(ip); mac != "" {
			return mac
		}
	}
	return ""
}

func (t *Table) LookupHostname(ip, mac string) string {
	for _, r := range t.hostnameResolvers {
		if name := r.LookupHostnameByIP(ip); name != "" {
			return name
		}
		if name := r.LookupHostnameByMac(mac); name != "" {
			return name
		}
	}
	return ""
}

func (t *Table) discoverDHCP() bool {
	if t.cfg.Service.DiscoverDHCP == nil {
		return true
	}
	return *t.cfg.Service.DiscoverDHCP
}

func (t *Table) discoverARP() bool {
	if t.cfg.Service.DiscoverARP == nil {
		return true
	}
	return *t.cfg.Service.DiscoverARP
}

func (t *Table) discoverMDNS() bool {
	if t.cfg.Service.DiscoverMDNS == nil {
		return true
	}
	return *t.cfg.Service.DiscoverMDNS
}

func (t *Table) discoverPTR() bool {
	if t.cfg.Service.DiscoverPtr == nil {
		return true
	}
	return *t.cfg.Service.DiscoverPtr
}

// normalizeIP normalizes the ip parsed from dnsmasq/dhcpd lease file.
func normalizeIP(in string) string {
	// dnsmasq may put ip with interface index in lease file, strip it here.
	ip, _, found := strings.Cut(in, "%")
	if found {
		return ip
	}
	return in
}

func normalizeHostname(name string) string {
	if before, _, found := strings.Cut(name, "."); found {
		return before // remove ".local.", ".lan.", ... suffix
	}
	return name
}

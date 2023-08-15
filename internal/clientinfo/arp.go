package clientinfo

import "sync"

type arpDiscover struct {
	mac sync.Map // ip  => mac
	ip  sync.Map // mac => ip
}

func (a *arpDiscover) refresh() error {
	a.scan()
	return nil
}

func (a *arpDiscover) LookupIP(mac string) string {
	val, ok := a.ip.Load(mac)
	if !ok {
		return ""
	}
	return val.(string)
}

func (a *arpDiscover) LookupMac(ip string) string {
	val, ok := a.mac.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

func (a *arpDiscover) String() string {
	return "arp"
}

func (a *arpDiscover) List() []string {
	var ips []string
	a.ip.Range(func(key, value any) bool {
		ips = append(ips, value.(string))
		return true
	})
	a.mac.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}

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

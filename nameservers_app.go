package ctrld

import (
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

// appNameserverList holds the nameservers that the host app reports. It is
// nil when the app reports none.
var appNameserverList atomic.Pointer[[]string]

// SetAppNameservers makes nss the nameservers of the system, in place of the
// nameservers that ctrld finds itself. A mobile app supplies them, because
// ctrld cannot read the network configuration from the app sandbox. Values
// that are not IP addresses are ignored. With no valid value, ctrld finds the
// nameservers itself again. It is safe for concurrent use.
func SetAppNameservers(nss []string) {
	valid := ParseNameservers(nss)
	if len(valid) == 0 {
		appNameserverList.Store(nil)
		return
	}
	appNameserverList.Store(&valid)
}

// ParseNameservers returns the IP addresses in nss, without duplicates and in
// the same order. It logs each value that is not an IP address, because an
// app that sends host:port values or names gets no other sign of the error.
func ParseNameservers(nss []string) []string {
	var valid []string
	for _, ns := range nss {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		addr, err := netip.ParseAddr(ns)
		if err != nil {
			ProxyLogger.Load().Warn().Msgf("ignoring app nameserver %q: not an IP address", ns)
			continue
		}
		if !slices.Contains(valid, addr.String()) {
			valid = append(valid, addr.String())
		}
	}
	return valid
}

// AppNameservers returns a copy of the nameservers that the app reports, or
// nil when the app reports none.
func AppNameservers() []string {
	nss := appNameserverList.Load()
	if nss == nil {
		return nil
	}
	return slices.Clone(*nss)
}

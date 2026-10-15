package cli

import (
	"strings"
	"sync/atomic"
)

// activeDirectoryDomain is the machine's Active Directory domain, recorded when
// addExtraSplitDnsRule detects it (Windows only; empty elsewhere).
//
// Names in it are resolved by the domain controller through upstream.os. The
// OS resolver races the LAN servers against Control D's public resolver unless
// the query is marked as a LAN query, and a split-rule match returns before
// that marking, so without this AD names (DC hostnames, DC-locator SRV
// records carrying the machine name, WPAD) were sent to 76.76.2.0 in plaintext.
var activeDirectoryDomain atomic.Pointer[string]

func setActiveDirectoryDomain(domain string) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	activeDirectoryDomain.Store(&d)
}

// inActiveDirectoryDomain reports whether name is the AD domain or below it.
func inActiveDirectoryDomain(name string) bool {
	d := activeDirectoryDomain.Load()
	if d == nil || *d == "" {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == *d || strings.HasSuffix(name, "."+*d)
}

// osUpstreamOnly reports whether upstreams is exactly the OS resolver.
func osUpstreamOnly(upstreams []string) bool {
	return len(upstreams) == 1 && upstreams[0] == upstreamOS
}

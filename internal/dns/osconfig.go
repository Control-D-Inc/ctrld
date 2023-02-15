// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bufio"
	"fmt"
	"net/netip"

	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

var _ OSConfigurator = (*directManager)(nil)

// An OSConfigurator applies DNS settings to the operating system.
type OSConfigurator interface {
	// SetDNS updates the OS's DNS configuration to match cfg.
	// If cfg is the zero value, all ctrld-related DNS
	// configuration is removed.
	// SetDNS must not be called after Close.
	// SetDNS takes ownership of cfg.
	SetDNS(cfg OSConfig) error

	// Close removes ctrld-related DNS configuration from the OS.
	Close() error

	Mode() string
}

// HostEntry represents a single line in the OS's hosts file.
type HostEntry struct {
	Addr  netip.Addr
	Hosts []string
}

// OSConfig is an OS DNS configuration.
type OSConfig struct {
	// Hosts is a map of DNS FQDNs to their IPs, which should be added to the
	// OS's hosts file. Currently, (2022-08-12) it is only populated for Windows
	// in SplitDNS mode and with Smart Name Resolution turned on.
	Hosts []*HostEntry
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netip.Addr
	// SearchDomains are the domain suffixes to use when expanding
	// single-label name queries. SearchDomains is additive to
	// whatever non-Tailscale search domains the OS has.
	SearchDomains []dnsname.FQDN
	// MatchDomains are the DNS suffixes for which Nameservers should
	// be used. If empty, Nameservers is installed as the "primary" resolver.
	MatchDomains []dnsname.FQDN
}

func (o OSConfig) IsZero() bool {
	return len(o.Nameservers) == 0 && len(o.SearchDomains) == 0 && len(o.MatchDomains) == 0
}

func (a OSConfig) Equal(b OSConfig) bool {
	if len(a.Nameservers) != len(b.Nameservers) {
		return false
	}
	if len(a.SearchDomains) != len(b.SearchDomains) {
		return false
	}
	if len(a.MatchDomains) != len(b.MatchDomains) {
		return false
	}

	for i := range a.Nameservers {
		if a.Nameservers[i] != b.Nameservers[i] {
			return false
		}
	}
	for i := range a.SearchDomains {
		if a.SearchDomains[i] != b.SearchDomains[i] {
			return false
		}
	}
	for i := range a.MatchDomains {
		if a.MatchDomains[i] != b.MatchDomains[i] {
			return false
		}
	}

	return true
}

// Format implements the fmt.Formatter interface to ensure that Hosts is
// printed correctly (i.e. not as a bunch of pointers).
//
// Fixes https://github.com/tailscale/tailscale/issues/5669
func (a OSConfig) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		_, _ = w.WriteString(`{Nameservers:[`)
		for i, ns := range a.Nameservers {
			if i != 0 {
				_, _ = w.WriteString(" ")
			}
			_, _ = fmt.Fprintf(w, "%+v", ns)
		}
		_, _ = w.WriteString(`] SearchDomains:[`)
		for i, domain := range a.SearchDomains {
			if i != 0 {
				_, _ = w.WriteString(" ")
			}
			_, _ = fmt.Fprintf(w, "%+v", domain)
		}
		_, _ = w.WriteString(`] MatchDomains:[`)
		for i, domain := range a.MatchDomains {
			if i != 0 {
				_, _ = w.WriteString(" ")
			}
			_, _ = fmt.Fprintf(w, "%+v", domain)
		}
		_, _ = w.WriteString(`] Hosts:[`)
		for i, host := range a.Hosts {
			if i != 0 {
				_, _ = w.WriteString(" ")
			}
			_, _ = fmt.Fprintf(w, "%+v", host)
		}
		_, _ = w.WriteString(`]}`)
	}).Format(f, verb)
}

package cli

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

// osResolverStaleHold bounds how long the OS resolver's nameservers count as
// read before the last network change, when no read finds new ones.
const osResolverStaleHold = 30 * time.Second

// After a network change, the OS resolver keeps the previous network's
// nameservers until a read finds the new ones. In Standard mode that read
// usually has to wait for the recovery to remove ctrld's DNS settings: while
// ctrld's own address is the configured server, the system reports nothing
// else, and on macOS an RDNSS-only IPv6 network has no other source.
//
// macOS discovers the NAT64 prefix of an IPv6-only network by resolving
// ipv4only.arpa (RFC 7050), through ctrld while ctrld is still the system
// resolver. A SERVFAIL from the previous network's nameservers ends that
// discovery, and macOS then never starts its CLAT, which an IPv4-only upstream
// needs to come back (#628). So while the nameservers are stale, ctrld sends
// no answer to that lookup when it fails, and macOS retries it, by then
// against the new network's resolver.

// markOSResolverStale records a network change the OS resolver may predate.
func (p *prog) markOSResolverStale() {
	p.osResolverStaleUntil.Store(networkEventsNowFn().Add(osResolverStaleHold).UnixNano())
}

// noteOSResolverRead records the result of a nameserver read: a read that
// found nameservers holds the current network's, so they are no longer stale.
// A read that found none kept the stale ones.
func (p *prog) noteOSResolverRead(ns []string) {
	if len(ns) > 0 {
		p.osResolverStaleUntil.Store(0)
	}
}

// osResolverStale reports whether the OS resolver still holds nameservers
// read before the last network change.
func (p *prog) osResolverStale() bool {
	return networkEventsNowFn().UnixNano() < p.osResolverStaleUntil.Load()
}

// isNAT64DiscoveryQuery reports whether msg is the RFC 7050 NAT64 prefix
// discovery lookup, AAAA for ipv4only.arpa.
func isNAT64DiscoveryQuery(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) != 1 {
		return false
	}
	q := msg.Question[0]
	return q.Qtype == dns.TypeAAAA && strings.EqualFold(dns.Fqdn(q.Name), dns64WellKnownName)
}

// readOSResolverOnNetworkChange marks the OS resolver stale and reads the new
// network's nameservers once, without waiting for the system to publish them:
// in Standard mode ctrld's own address is still the configured server here,
// and on macOS a full read retries scutil for about a second while holding the
// lock that every OS resolver query takes. Where the system does report the
// new nameservers, as in intercept mode or with DHCPv4, the read replaces the
// stale ones before the re-bootstrap.
func (p *prog) readOSResolverOnNetworkChange(ctx context.Context) {
	p.markOSResolverStale()
	ns := initializeOsResolverQuick(ctrld.LoggerCtx(ctx, p.logger.Load()), osResolverReasonNetworkChange)
	p.noteOSResolverRead(ns)
	if len(ns) > 0 {
		p.Debug().Msgf("Network change: OS resolver nameservers: %v", ns)
	} else {
		p.Debug().Msg("Network change: no new OS resolver nameservers yet; holding failed ipv4only.arpa lookups until they are read")
	}
}

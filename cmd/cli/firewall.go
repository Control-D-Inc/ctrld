package cli

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/firewall"
)

// firewallModeEnabled reports whether firewall mode is active for this prog instance.
func (p *prog) firewallModeEnabled() bool {
	return p.firewallAllowList() != nil
}

// firewallAllowList returns the allowlist this run enforces, or nil when Firewall
// Mode is off.
//
// syncFirewallMode replaces the field from the reload goroutine while refreshes
// read it, so a read that is followed by a dereference has to work from a
// snapshot rather than from the field: otherwise a reload landing in between
// turns the pointer to nil under the caller. Acting on a superseded allowlist is
// harmless - reconcileDestinations re-checks the firewall generation under
// destinationsMu and does nothing for a generation that has ended.
func (p *prog) firewallAllowList() *firewall.AllowList {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allowList
}

// setFirewallAllowList publishes this run's allowlist. Only syncFirewallMode
// calls it; every other goroutine reads through firewallAllowList.
func (p *prog) setFirewallAllowList(al *firewall.AllowList) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowList = al
}

// initFirewallAllowList populates the permanent allowlist entries and starts the
// background reaper. Called once during prog.run() when firewall_mode is "on".
//
// Permanent entries include:
//   - Loopback (127.0.0.0/8, ::1)
//   - RFC1918 private ranges (configurable — enabled by default)
//   - Link-local (169.254.0.0/16, fe80::/10)
//   - CGNAT range (100.64.0.0/10) — used by Tailscale, carrier NAT
//   - ctrld listener IPs
//   - DoH/DoT/DoQ upstream resolver IPs
//   - ControlD API and upgrade download server IPs
func (p *prog) initFirewallAllowList(ctx context.Context, al *firewall.AllowList) {
	// Loopback.
	al.AddPermanentPrefix(netip.MustParsePrefix("127.0.0.0/8"))
	al.AddPermanent(netip.MustParseAddr("::1"))

	// RFC1918 private ranges — needed for LAN access, printers, NAS, etc.
	al.AddPermanentPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	al.AddPermanentPrefix(netip.MustParsePrefix("172.16.0.0/12"))
	al.AddPermanentPrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Link-local.
	al.AddPermanentPrefix(netip.MustParsePrefix("169.254.0.0/16"))
	al.AddPermanentPrefix(netip.MustParsePrefix("fe80::/10"))

	// CGNAT range — used by Tailscale (100.x.x.x), carrier-grade NAT, etc.
	al.AddPermanentPrefix(netip.MustParsePrefix("100.64.0.0/10"))

	// Multicast.
	al.AddPermanentPrefix(netip.MustParsePrefix("224.0.0.0/4"))
	al.AddPermanentPrefix(netip.MustParsePrefix("ff00::/8"))

	// ctrld listener IPs — traffic to ourselves must always be allowed.
	for _, lc := range p.cfg.Listener {
		if ip, err := netip.ParseAddr(lc.IP); err == nil {
			al.AddPermanent(ip)
		}
	}

	// Upstream resolver IPs — ctrld needs to reach its upstreams.
	p.addUpstreamIPsToPermanent(al)

	// ControlD API and download IPs — ctrld needs to reach its own control plane.
	p.addControlDEndpointIPsToPermanent(al)

	// Platform-specific enforcement (pf on macOS, WFP on Windows) is initialized
	// from postRun() after startDNSIntercept() has prepared dnsInterceptState.

	p.Info().Msgf("Firewall allowlist initialized with %d permanent entries",
		al.Stats().PermanentIPs)
}

// syncFirewallMode applies the current firewall_mode setting for this run.
// Reloads create a new run-scoped context, so background firewall workers must
// be restarted each run even when the allowlist object is reused.
func (p *prog) syncFirewallMode(ctx context.Context) {
	// This is the only writer of p.allowList, so its own reads need no lock; every
	// other goroutine reads the published pointer through firewallAllowList.
	al := p.allowList

	if p.cfg.Service.FirewallMode != "on" {
		if al != nil || p.platformFirewallState != nil {
			p.Info().Msg("Firewall mode disabled: removing platform enforcement and clearing allowlist")
		}
		if al != nil {
			al.SetOnChange(nil)
			al.SetOnBatchChange(nil)
			p.setFirewallAllowList(nil)
		}
		// Platform enforcement is torn down below, so nothing may be mirrored any
		// more: end this generation, which retires the maintenance worker, and
		// forget what was applied so a later re-enable reinstalls it.
		p.retireFirewallDestinations()
		if p.platformFirewallState != nil {
			p.shutdownPlatformFirewall()
			p.platformFirewallState = nil
		}
		return
	}

	if al == nil {
		al = firewall.New()
		p.initFirewallAllowList(ctx, al)
		p.setFirewallAllowList(al)
		if service.Interactive() {
			p.Warn().Msg("Firewall mode has no effect in interactive mode; run ctrld as a service for enforcement")
		} else {
			p.Info().Msg("Firewall mode enabled: only DNS-resolved IPs will be allowed")
		}
	} else {
		p.addUpstreamIPsToPermanent(al)
		p.addControlDEndpointIPsToPermanent(al)
	}

	// Open this run's firewall generation before any work is scheduled against it,
	// so the previous run's maintenance worker stops acting on enforcement this
	// run is now responsible for.
	gen := p.startFirewallGeneration()

	// Apply the organization's allowed destinations from the resolver config this
	// run started with. A reload that turns Firewall Mode on builds a fresh
	// allowlist, so the set has to be re-applied rather than assumed present.
	p.syncAllowedDestinations()

	// The run context is canceled on each reload. Restart the reaper/maintenance
	// workers for this run so reused allowlists keep expiring entries.
	al.StartReaper(ctx)
	go p.firewallMaintenance(ctx, al, gen)

	// On reload, postRun() is not called, so initialize platform enforcement here
	// if intercept state already exists. Initial startup still defers to postRun()
	// because DNS intercept state is prepared there.
	//
	// Called whether or not enforcement is already up, because the permanent adds
	// above reach memory only: AddPermanent fires no change callback, so a reload
	// that resolves a new API address would log it as permitted while the platform
	// never hears about it. Each platform's re-entry is a refresh - Windows
	// reinstalls the permanent filters it is missing, macOS returns early - so
	// calling it when enforcement is already up costs nothing and closes that gap.
	if p.dnsInterceptState != nil {
		p.initPlatformFirewall()
	}
}

// addUpstreamIPsToPermanent resolves upstream endpoint hostnames and adds their
// IPs to the permanent allowlist. Called at startup and on config reload.
func (p *prog) addUpstreamIPsToPermanent(al *firewall.AllowList) {
	for _, uc := range p.cfg.Upstream {
		if uc == nil || uc.Endpoint == "" {
			continue
		}
		// Extract host from the endpoint URL.
		host := extractHostFromEndpoint(uc.Endpoint)
		if host == "" {
			continue
		}

		// If it's already an IP, add directly.
		if ip, err := netip.ParseAddr(host); err == nil {
			al.AddPermanent(ip)
			p.Debug().Msgf("Firewall: added upstream IP %s to permanent allowlist", ip)
			continue
		}

		// Resolve hostname to IPs.
		ips, err := net.LookupHost(host)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: could not resolve upstream host %s", host)
			continue
		}
		for _, ipStr := range ips {
			if ip, err := netip.ParseAddr(ipStr); err == nil {
				al.AddPermanent(ip)
				p.Debug().Msgf("Firewall: added upstream IP %s (%s) to permanent allowlist", ip, host)
			}
		}
	}
}

// syncAllowedDestinations applies the organization's Allowed Destination IP list
// from the resolver config currently held by prog.
//
// Called whenever that config could have changed: on every start and reload (via
// syncFirewallMode) and after every API refresh, forced or scheduled (via
// apiConfigReload). Reading the list from p.rc rather than taking it as an
// argument keeps those callers from having to know whether Firewall Mode is on.
func (p *prog) syncAllowedDestinations() {
	p.mu.Lock()
	rc := p.rc
	al := p.allowList
	p.mu.Unlock()

	var entries []string
	if rc != nil {
		entries = rc.DestinationIPs
	}
	p.applyAllowedDestinations(al, entries)
}

// applyAllowedDestinations records entries as the desired Firewall Mode exception
// set and mirrors it into platform enforcement. Entries the API sent that are not
// a valid address or CIDR are dropped individually, so one bad entry never voids
// the rest of an organization's list.
//
// A no-op when Firewall Mode is off: with no allowlist there is nothing to
// except from, and the set is re-applied from p.rc if the mode is turned on.
//
// The allowlist is an argument rather than a field read because a reload can
// replace p.allowList - including with nil - between the nil check and the
// SetExceptions call below, which would dereference nil. Callers snapshot it
// once under mu (see firewallAllowList) and pass what they snapshotted.
func (p *prog) applyAllowedDestinations(al *firewall.AllowList, entries []string) {
	if al == nil {
		return
	}

	prefixes, rejected, wide := parseAllowedDestinations(entries)
	p.warnRejectedAllowedDestinations(rejected)
	p.warnWideAllowedDestinations(wide)

	al.SetExceptions(prefixes)
	p.reconcileDestinations(al, p.firewallGen.Load())
}

// reconcileAllowedDestinations brings platform enforcement in line with the
// desired allowed-destination set, installing what is missing and removing what
// the organization has withdrawn.
//
// The applied snapshot advances ONLY after the platform accepted the change. A
// failed pfctl call or WFP filter operation therefore leaves the previous
// snapshot recorded, so the same delta is recomputed - and retried - by the next
// refresh and by the periodic reconcile, instead of being silently dropped while
// the logs claim the new set is in force. Retrying the whole delta is safe
// because both mirrors are idempotent: installing an entry that is already there
// and removing one that is already gone are no-ops.
//
// Callers must not hold destinationsMu; the mirror can block on pfctl.
func (p *prog) reconcileAllowedDestinations() {
	p.reconcileDestinations(p.firewallAllowList(), p.firewallGen.Load())
}

// reconcileDestinations is reconcileAllowedDestinations for one firewall
// generation. Background workers pass the allowlist and generation they were
// started with, and the generation is re-checked under destinationsMu: teardown
// bumps it while holding the same lock, so a worker from a previous run can never
// mirror anything into enforcement that is being (or has been) removed.
func (p *prog) reconcileDestinations(al *firewall.AllowList, gen uint64) {
	if al == nil {
		return
	}
	desired := al.Exceptions()

	p.destinationsMu.Lock()
	defer p.destinationsMu.Unlock()

	if p.firewallGen.Load() != gen {
		return
	}

	// A resync owes the platform the whole set, not a delta: it means enforcement
	// started with state ctrld does not know (a persist pf table from a previous
	// run) or with none at all. Until the replace succeeds nothing about the
	// applied set can be assumed, so the flag stays set and it is retried.
	if p.destinationsNeedResync {
		if err := firewallReplaceExceptionsFn(p, desired); err != nil {
			p.Warn().Err(err).Int("total", len(desired)).
				Msg("Firewall: could not install organization allowed destinations, will retry")
			return
		}
		p.destinationsNeedResync = false
		p.appliedDestinations = desired
		p.logDestinationChange(len(desired), 0, desired, nil)
		return
	}

	added := prefixesNotIn(desired, p.appliedDestinations)
	removed := prefixesNotIn(p.appliedDestinations, desired)
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	if err := firewallMirrorExceptionsFn(p, added, removed); err != nil {
		p.Warn().Err(err).
			Int("pending_add", len(added)).
			Int("pending_remove", len(removed)).
			Msg("Firewall: could not apply all organization allowed destinations, will retry")
		return
	}

	p.appliedDestinations = desired
	p.logDestinationChange(len(added), len(removed), added, removed)
}

// logDestinationChange reports an applied change: counts at Info, addresses at
// Debug. The list is an organization's network topology, and Info-level logs are
// persisted and uploaded with support bundles, so the counts are all that goes
// into the routine record.
func (p *prog) logDestinationChange(nAdded, nRemoved int, added, removed []netip.Prefix) {
	p.Info().
		Int("added", nAdded).
		Int("removed", nRemoved).
		Int("total", len(p.appliedDestinations)).
		Msg("Firewall: applied organization allowed destination IPs")
	p.Debug().
		Strs("added", prefixStrings(added)).
		Strs("removed", prefixStrings(removed)).
		Msg("Firewall: organization allowed destination changes")
}

// pendingDestinations reports how many allowed-destination changes platform
// enforcement has not accepted yet. Non-zero means a mirror attempt failed and
// the reconcile is still retrying, which is the difference between "the set is in
// force" and "the set is what we want" - the stats line must not conflate them.
func (p *prog) pendingDestinations(al *firewall.AllowList) int {
	if al == nil {
		return 0
	}
	desired := al.Exceptions()

	p.destinationsMu.Lock()
	defer p.destinationsMu.Unlock()

	if p.destinationsNeedResync {
		// Nothing about the applied set is known, so everything is outstanding -
		// and an empty desired set still owes the platform a flush of whatever it
		// is holding, which is one pending operation, not zero.
		return max(len(desired), 1)
	}
	return len(prefixesNotIn(desired, p.appliedDestinations)) + len(prefixesNotIn(p.appliedDestinations, desired))
}

// startFirewallGeneration opens a new firewall generation and returns it,
// retiring the workers of the previous one. Called for every run (start or
// reload) that has Firewall Mode on; the applied snapshot is left alone because
// platform enforcement survives a reload.
func (p *prog) startFirewallGeneration() uint64 {
	p.destinationsMu.Lock()
	defer p.destinationsMu.Unlock()
	return p.firewallGen.Add(1)
}

// markDestinationsForResync records that platform enforcement holds unknown
// state, so the next reconcile replaces its whole allowed-destination set rather
// than applying a delta against a snapshot that no longer describes anything.
// Called when enforcement starts: a fresh WFP session holds nothing, and a pf
// persist table may still hold what a previous run put there.
func (p *prog) markDestinationsForResync() {
	p.destinationsMu.Lock()
	defer p.destinationsMu.Unlock()
	p.appliedDestinations = nil
	p.destinationsNeedResync = true
}

// retireFirewallDestinations ends the current firewall generation and forgets the
// applied set, for teardown: enforcement is about to be removed, so there is
// nothing left to reconcile against and no resync to owe.
//
// Bumping the generation under destinationsMu is what makes teardown safe against
// the maintenance worker: either the worker is mid-reconcile and this blocks
// until it finishes, or it reaches its own reconcile afterwards, sees a
// generation it does not own, and does nothing.
func (p *prog) retireFirewallDestinations() {
	p.destinationsMu.Lock()
	defer p.destinationsMu.Unlock()
	p.firewallGen.Add(1)
	p.appliedDestinations = nil
	p.destinationsNeedResync = false
}

// firewallMirrorExceptionsFn mirrors an allowed-destination delta into platform
// enforcement, and firewallReplaceExceptionsFn makes enforcement hold exactly the
// given set regardless of what it held before. Indirected so the
// failure-and-retry paths are testable without pf or WFP.
var (
	firewallMirrorExceptionsFn  = (*prog).firewallApplyExceptionsPlatform
	firewallReplaceExceptionsFn = (*prog).firewallReplaceExceptionsPlatform
)

// prefixesNotIn returns the members of a that are absent from b.
func prefixesNotIn(a, b []netip.Prefix) []netip.Prefix {
	if len(a) == 0 {
		return nil
	}
	inB := make(map[netip.Prefix]struct{}, len(b))
	for _, prefix := range b {
		inB[prefix] = struct{}{}
	}
	var out []netip.Prefix
	for _, prefix := range a {
		if _, ok := inB[prefix]; ok {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

// parseAllowedDestinations converts the API's Allowed Destination IP entries into
// prefixes, returning the usable ones and the raw entries that were rejected.
//
// The API reports a single host as a bare address ("1.2.3.4", "2606:1a40::1") and
// anything wider in CIDR form, so both spellings are accepted; a bare address
// becomes a single-host prefix. IPv4-in-IPv6 forms are unmapped to match how the
// allowlist stores addresses, otherwise a "::ffff:1.2.3.4" entry would never
// match the IPv4 address it denotes.
// The third result is the accepted prefixes that are wide enough to be worth
// reporting; see wideAllowedDestination.
func parseAllowedDestinations(entries []string) (accepted []netip.Prefix, rejected []string, wide []netip.Prefix) {
	if len(entries) == 0 {
		return nil, nil, nil
	}
	accepted = make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefix = unmapPrefix(prefix)
			accepted = append(accepted, prefix)
			if wideAllowedDestination(prefix) {
				wide = append(wide, prefix)
			}
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			accepted = append(accepted, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		rejected = append(rejected, entry)
	}
	return accepted, rejected, wide
}

// An accepted prefix with fewer mask bits than these is reported. The floors are
// set below anything an organization plausibly means: /8 is the widest classical
// IPv4 network and the size of RFC1918's 10.0.0.0/8, and /32 is a whole IPv6 RIR
// allocation. A bare address always parses to a single-host prefix, so only a
// CIDR entry can reach either floor.
const (
	minSaneAllowedDestinationV4Bits = 8
	minSaneAllowedDestinationV6Bits = 32
)

// wideAllowedDestination reports whether an accepted prefix covers enough of the
// address space to deserve a line in the log.
//
// netip.ParsePrefix takes "1.2.3.4/0", and normalizeExceptions masks it to
// 0.0.0.0/0; "::/0" and - through unmapPrefix - "::ffff:0:0/96" do the same for
// IPv6. One such entry lets every destination of that family bypass Firewall
// Mode while the mode still reports on, and logDestinationChange records only
// counts at Info, so without this the bypass is invisible outside Debug logs.
//
// This is not a defence against a hostile API, which can already turn the mode
// off through custom_config. It is a defence against a wide prefix arriving by
// accident - a dashboard bug, or an admin who typed the wrong mask - and nobody
// noticing.
func wideAllowedDestination(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() < minSaneAllowedDestinationV4Bits
	}
	return prefix.Bits() < minSaneAllowedDestinationV6Bits
}

// unmapPrefix rewrites an IPv4-in-IPv6 prefix to its IPv4 form, adjusting the
// mask by the 96-bit IPv4-mapped prefix length. Prefixes of other families are
// returned unchanged.
func unmapPrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if !addr.Is4In6() {
		return prefix
	}
	bits := prefix.Bits() - 96
	if bits < 0 {
		// A mask wider than the mapped range does not denote an IPv4 network;
		// leave it as the IPv6 prefix it literally is.
		return prefix
	}
	return netip.PrefixFrom(addr.Unmap(), bits)
}

// warnRejectedAllowedDestinations reports unusable entries, but only when the set
// of rejections changes. The list is re-parsed on every refresh (hourly by
// default), so warning unconditionally would repeat the same lines for the life
// of the process while still saying nothing new.
// The rejected values themselves go to Debug, never to Warn. A rejected entry is
// still an organization's topology - "10.0.0.0/33" names a real network - and
// Warn logs are persisted and travel in support bundles exactly like Info ones,
// so they follow the same rule as logDestinationChange: counts in the routine
// record, addresses only when someone turned Debug on to look.
func (p *prog) warnRejectedAllowedDestinations(rejected []string) {
	key := strings.Join(rejected, ",")

	p.mu.Lock()
	unchanged := p.rejectedDestinationsKey == key
	p.rejectedDestinationsKey = key
	p.mu.Unlock()

	if unchanged || len(rejected) == 0 {
		return
	}
	p.Warn().Int("rejected", len(rejected)).
		Msg("Firewall: ignoring organization allowed destinations that are not a valid IP address or CIDR")
	p.Debug().Strs("values", rejected).
		Msg("Firewall: rejected organization allowed destinations")
}

// warnWideAllowedDestinations reports accepted entries wide enough to blanket an
// address family, with the mask width but not the address, and only when the set
// of them changes - the list is re-parsed on every refresh, so an unconditional
// warning would repeat the same lines for the life of the process.
func (p *prog) warnWideAllowedDestinations(wide []netip.Prefix) {
	key := strings.Join(prefixStrings(wide), ",")

	p.mu.Lock()
	unchanged := p.wideDestinationsKey == key
	p.wideDestinationsKey = key
	p.mu.Unlock()

	if unchanged || len(wide) == 0 {
		return
	}
	for _, prefix := range wide {
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		p.Warn().Str("family", family).Int("bits", prefix.Bits()).
			Msg("Firewall: organization allowed destination covers a very wide range; traffic to it bypasses Firewall Mode")
	}
	p.Debug().Strs("values", prefixStrings(wide)).
		Msg("Firewall: wide organization allowed destinations")
}

// prefixStrings renders prefixes for logging.
func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

// addControlDEndpointIPsToPermanent permits the ControlD endpoints ctrld dials on
// its own behalf. Called at startup and on config reload, like the upstream IPs.
//
// Firewall Mode permits what ctrld's listener resolved, and each of these has a
// hardcoded address it dials when DNS is unusable - which is exactly the state a
// ctrld blocked by its own filters is in. Nothing teaches the allowlist about
// those addresses, so the block-all filters deny ctrld's own sockets. See
// controld.APIEndpointIPs for the incident this comes from.
func (p *prog) addControlDEndpointIPsToPermanent(al *firewall.AllowList) {
	// The API. Its transport resolves with ctrld.LookupIP, which queries the OS
	// nameservers directly rather than through the listener, so neither what it
	// resolves nor what it falls back to is ever learned - both are permitted here.
	p.addPermanentIPs(al, "ControlD API", controld.APIEndpointIPs(cdDev))
	p.addPermanentResolvedIPs(al, "ControlD API", controld.APIDomain(cdDev))

	// The upgrade download server. performUpgrade spawns a detached child process,
	// which WFP's block-all filters deny exactly like this one: they carry no
	// process condition. Its hostname lookup does go through the listener and is
	// learned, so only the direct IP it falls back to needs permitting - and that
	// fallback is the one an upgrade on a blocked host depends on.
	p.addPermanentIPs(al, "ControlD download server", []string{downloadServerIp})
}

// addPermanentIPs permits literal addresses, ignoring any that do not parse.
func (p *prog) addPermanentIPs(al *firewall.AllowList, what string, ips []string) {
	for _, ipStr := range ips {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			al.AddPermanent(ip)
			p.Debug().Msgf("Firewall: added %s IP %s to permanent allowlist", what, ip)
		}
	}
}

// addPermanentResolvedIPs permits whatever domain resolves to right now.
func (p *prog) addPermanentResolvedIPs(al *firewall.AllowList, what, domain string) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		// Neither fatal nor surprising during early startup, and not a Warn: the
		// direct addresses are permitted regardless, and they are what the
		// transport itself falls back to in this same situation.
		p.Debug().Err(err).Msgf("Firewall: could not resolve %s for the permanent allowlist; its direct IPs are permitted", domain)
		return
	}
	for _, ipStr := range ips {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			al.AddPermanent(ip)
			p.Debug().Msgf("Firewall: added %s IP %s (%s) to permanent allowlist", what, ip, domain)
		}
	}
}

// extractHostFromEndpoint extracts the hostname or IP from a DoH/DoT/DoQ endpoint URL.
// Handles formats like:
//   - "https://dns.controld.com/abcdef"
//   - "tls://dns.controld.com"
//   - "quic://dns.controld.com:784"
//   - "1.2.3.4:53"
//   - "sdns://..." (DNS stamps — host is encoded inside, skip)
func extractHostFromEndpoint(endpoint string) string {
	// DNS stamps encode the server info in base64 — we can't extract the host
	// without decoding. The upstream IPs will be resolved by the sdns upstream
	// initialization path at runtime.
	if strings.HasPrefix(endpoint, "sdns://") {
		return ""
	}

	// Try parsing as URL first (covers https://, tls://, quic://).
	if host := extractHostFromURL(endpoint); host != "" {
		return host
	}

	// Try as host:port.
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return host
	}

	// Try as bare IP.
	if _, err := netip.ParseAddr(endpoint); err == nil {
		return endpoint
	}

	return ""
}

// extractHostFromURL extracts the host from a URL string.
func extractHostFromURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// firewallRecordResolvedIPs extracts A and AAAA records from a DNS response
// and adds them to the firewall allowlist. Called from postProcessStandardQuery()
// after a successful DNS resolution.
//
// This is the primary feed for the allowlist — every IP that ctrld resolves
// gets added here, making it allowed for outbound connections.
func (p *prog) firewallRecordResolvedIPs(answer *dns.Msg, domain string) {
	if p.allowList == nil || answer == nil {
		return
	}

	// Only record IPs from successful responses.
	if answer.Rcode != dns.RcodeSuccess {
		return
	}

	for _, rr := range answer.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(r.A); ok {
				ttl := time.Duration(r.Hdr.Ttl) * time.Second
				if ttl < 30*time.Second {
					// Enforce minimum TTL to prevent constant churn for very short TTLs.
					ttl = 30 * time.Second
				}
				p.allowList.Add(ip, domain, ttl)
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(r.AAAA); ok {
				ttl := time.Duration(r.Hdr.Ttl) * time.Second
				if ttl < 30*time.Second {
					ttl = 30 * time.Second
				}
				p.allowList.Add(ip, domain, ttl)
			}
		case *dns.CNAME:
			// For CNAME chains: the final A/AAAA records will be caught above.
			// We don't need to do anything special for the CNAME itself, but we
			// log it for debugging CNAME chain issues.
			p.Debug().Msgf("Firewall: CNAME %s → %s (IPs from target will be allowlisted)", domain, r.Target)
		}
	}
}

// firewallOnConfigReload is called when apiConfigReload() detects a config change.
// It flushes the entire allowlist so that DNS queries against the new policy
// repopulate it with the correct set of allowed IPs.
//
// This is the simple approach (vs. selective re-resolution per domain).
// The tradeoff is a brief window where connections may fail until DNS cache
// repopulates. Apps that reconnect directly to a previously resolved IP without
// making a fresh DNS query can remain blocked longer; this is an explicit v1
// limitation to call out in release notes and app-compatibility testing.
func (p *prog) firewallOnConfigReload() {
	if p.allowList == nil {
		return
	}
	stats := p.allowList.Stats()
	p.Info().Msgf("Firewall: config reload detected, flushing allowlist (%d IPs, %d domains)",
		stats.AllowedIPs, stats.TrackedDomains)
	// Flush platform-specific state first (pf table / WFP filters),
	// then flush the allowlist. The AllowList's batch callbacks will
	// also fire, but the platform flush handles the bulk operation more
	// efficiently than removing IPs one-by-one.
	p.firewallFlushPlatform()
	p.allowList.Flush()
}

// firewallOnNetworkChange is called when monitorNetworkChanges() detects a major
// network transition (WiFi↔cellular, interface IP changes). Stale IPs from the
// old network may no longer be valid, so we flush and let DNS repopulate.
func (p *prog) firewallOnNetworkChange() {
	if p.allowList == nil {
		return
	}
	stats := p.allowList.Stats()
	p.Info().Msgf("Firewall: network change detected, flushing allowlist (%d IPs, %d domains)",
		stats.AllowedIPs, stats.TrackedDomains)
	p.firewallFlushPlatform()
	p.allowList.Flush()
}

// firewallMaintenance logs allowlist metrics immediately, then every 5 minutes
// while firewall mode is active, and retries any allowed-destination change that
// platform enforcement rejected.
//
// The retry has to be time-based, not only refresh-driven: configuration
// refreshes are hourly by default, so a transient pfctl or WFP failure would
// otherwise leave an approved destination blocked - or worse, a withdrawn one
// permitted - for up to an hour.
// It works on the allowlist and generation it was started with, not on
// p.allowList: a reload replaces that field from another goroutine, and this
// worker outlives the run whose context it was given by however long it takes to
// observe cancellation. Once its generation is over - a reload, or Firewall Mode
// being turned off - the worker retires rather than reconciling enforcement it no
// longer owns; reconcileDestinations re-checks the generation under
// destinationsMu, so even a worker that is already inside it cannot act late.
func (p *prog) firewallMaintenance(ctx context.Context, al *firewall.AllowList, gen uint64) {
	if al == nil {
		return
	}
	p.logFirewallStatsOnce(al)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A tick can win the select against an already-canceled context, and
			// a generation can end without the context being canceled at all.
			if ctx.Err() != nil || p.firewallGen.Load() != gen {
				return
			}
			p.reconcileDestinations(al, gen)
			p.logFirewallStatsOnce(al)
		}
	}
}

func (p *prog) logFirewallStatsOnce(al *firewall.AllowList) {
	if al == nil {
		return
	}
	stats := al.Stats()
	p.Info().
		Int("allowed_ips", stats.AllowedIPs).
		Int("permanent_ips", stats.PermanentIPs).
		Int("allowed_destinations", stats.ExceptionPrefixes).
		Int("allowed_destinations_pending", p.pendingDestinations(al)).
		Int("tracked_domains", stats.TrackedDomains).
		Int64("total_hits", stats.TotalHits).
		Int64("total_misses", stats.TotalMisses).
		Msg("Firewall allowlist stats")
}

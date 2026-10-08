//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// pfFirewallState holds the state for pf-based firewall mode enforcement on macOS.
// When firewall mode is active, we maintain a pf table of allowed IPs and add
// block/pass rules to the ctrld anchor that enforce the allowlist.
type pfFirewallState struct {
	// mu protects batch accumulation.
	mu sync.Mutex

	// pendingAdds and pendingRemoves accumulate changes for batched pf updates.
	pendingAdds    []netip.Addr
	pendingRemoves []netip.Addr

	// batchTimer fires after the accumulation window to flush pending changes.
	batchTimer *time.Timer

	// lastForwardedSources is the forwarded-source set (auto-detected VM networks +
	// configured) that pf has actually accepted, and lastForwardedKey its
	// order-independent signature. reconcileForwardedSources compares against these
	// to rebuild the anchor when guests appear/disappear, and to know which subnets
	// gained or lost trust so their stale pf states can be dropped. Both advance only
	// after a successful anchor load, so a failed reload is retried, never latched.
	lastForwardedSources []forwardedSource
	lastForwardedKey     string

	// applyForwardedMu serializes the compare-reload-record sequence in
	// applyForwardedSourceChange, so a watchdog tick and a network change cannot both
	// rebuild the anchor for the same transition or interleave their snapshot updates.
	// Separate from mu, which must not be held across pfctl execution.
	applyForwardedMu sync.Mutex
}

// forwardedSourceWarnTracker dedupes the "unusable configured entry" warning by
// signature. Config is re-parsed on every anchor build and every watchdog tick, so
// warning unconditionally would repeat the same line for the life of the process;
// comparing signatures still reports an entry a config reload has just introduced.
//
// Package-level rather than a pfFirewallState field because it has to work before
// that state exists: initPlatformFirewall defers pf enforcement until intercept mode
// starts, so Firewall Mode can be on with no pfFirewallState yet.
var forwardedSourceWarnTracker struct {
	mu  sync.Mutex
	key string
}

const (
	// pfFirewallTable is the pf table name for dynamically-allowed IPs.
	pfFirewallTable = "ctrld_allowed"

	// pfFirewallExceptionTable is the pf table name for the organization's
	// Allowed Destination IP list. Kept separate from pfFirewallTable so the
	// flushes that discard DNS-resolved IPs (config reload, network change)
	// leave administratively allowed destinations in place, and so a destination
	// removed upstream can be deleted without touching resolved entries.
	pfFirewallExceptionTable = "ctrld_allowed_dst"

	// pfFirewallBatchInterval is the accumulation window for batching pf table updates.
	// Short enough for responsiveness, long enough to avoid per-DNS-response pfctl calls.
	pfFirewallBatchInterval = 200 * time.Millisecond
)

// hypervisorVMNetPrefixes are interface-name prefixes that are specific to a
// virtualization vendor's private VM/NAT network, and therefore reliable proof of
// VM ownership by name alone.
//
// Two vendors still put the subnet directly on such an interface: Parallels (vnic0)
// and VirtualBox host-only (vboxnet0). vmnet* covers legacy kext-based VMware Fusion
// on Intel. They are also what proves ownership of a bridge they are a member of -
// see bridgeHasVMMember.
//
// On current macOS this is not sufficient on its own. vmnet.framework - which backs
// Virtualization.framework guests (UTM, Docker Desktop, Multipass, Fusion 12.1+ NAT)
// - puts the RFC1918 gateway address on a bridge10x interface and attaches the
// vendor-named vmenet* interface as an address-less member of it. Matching on name
// alone therefore never fires for those stacks, which is why bridge membership is
// checked too.
var hypervisorVMNetPrefixes = []string{
	"vmnet",   // VMware Fusion (legacy kext-based, Intel)
	"vmenet",  // vmnet.framework member interface (UTM, Docker, Multipass, Fusion 12.1+)
	"vnic",    // Parallels Desktop
	"vboxnet", // VirtualBox host-only
}

// isHypervisorVMNetIface reports whether an interface name is a known
// vendor-specific VM/NAT network (see hypervisorVMNetPrefixes).
func isHypervisorVMNetIface(name string) bool {
	for _, prefix := range hypervisorVMNetPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// isBridgeIface reports whether name is a macOS bridge interface.
//
// A bridge name is deliberately NOT treated as proof of anything: macOS uses this
// namespace for Thunderbolt/aggregated links too (this repo's own tunnel-change code
// lists bridge0 among physical interfaces), and auto-trusting those could force-route
// unrelated same-subnet traffic. Ownership comes from the member list instead.
func isBridgeIface(name string) bool {
	return strings.HasPrefix(name, "bridge")
}

// bridgeMembersFn returns a bridge's member interfaces. Indirected so detection can
// be tested without a hypervisor or ifconfig.
var bridgeMembersFn = bridgeMembers

// bridgeMembers returns the member interfaces of a macOS bridge, via ifconfig.
// There is no address-family-independent syscall for this that does not mean
// hand-rolling SIOCGDRVSPEC/BRDGGIFS structs, and this runs at most once per
// candidate bridge per anchor build.
func bridgeMembers(name string) []string {
	out, err := exec.Command("ifconfig", name).CombinedOutput()
	if err != nil {
		return nil
	}
	return parseBridgeMembers(string(out))
}

// parseBridgeMembers extracts member interface names from ifconfig output, which
// lists each as a line of the form "\tmember: vmenet0 flags=3<LEARNING,DISCOVER>".
func parseBridgeMembers(ifconfigOut string) []string {
	var members []string
	for _, line := range strings.Split(ifconfigOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "member:" {
			continue
		}
		members = append(members, fields[1])
	}
	return members
}

// bridgeHasVMMember reports whether a bridge's member list proves VM/NAT ownership,
// i.e. whether a vendor-specific VM interface is bridged into it.
//
// This is the ownership evidence a bridge name lacks. A vmnet.framework bridge has a
// vmenet* member; a Thunderbolt bridge has en* members and so is never trusted.
func bridgeHasVMMember(members []string) bool {
	for _, m := range members {
		if isHypervisorVMNetIface(m) {
			return true
		}
	}
	return false
}

// firewallFlushPlatform flushes the pf table on macOS.
func (p *prog) firewallFlushPlatform() {
	p.pfFirewallFlushTable()
}

// shutdownPlatformFirewall removes macOS firewall-mode dynamic state. The pf
// anchor itself is rebuilt by DNS intercept without firewall rules once
// p.allowList is nil.
func (p *prog) shutdownPlatformFirewall() {
	p.pfFirewallFlushTable()
	// The organization's allowed destinations live in their own persist table,
	// which the dynamic flush does not touch. Clear it too so turning Firewall
	// Mode off leaves no table content behind for a later run to inherit.
	if out, err := pfExceptionTableCommand("flush", nil); err != nil {
		p.Debug().Err(err).Str("output", strings.TrimSpace(string(out))).
			Msgf("Firewall: failed to flush pf table %s during shutdown (may not exist)", pfFirewallExceptionTable)
	}

	if p.dnsInterceptState == nil {
		return
	}

	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRules(vpnExemptions)
	if err := writePFAnchorFile(rulesStr); err != nil {
		p.Warn().Err(err).Msg("Firewall: failed to write pf anchor during shutdown")
		return
	}
	if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput(); err != nil {
		p.Warn().Err(err).Str("output", strings.TrimSpace(string(out))).Msg("Firewall: failed to reload pf anchor during shutdown")
	}
}

// initPlatformFirewall initializes macOS-specific firewall enforcement (pf tables).
func (p *prog) initPlatformFirewall() {
	if _, ok := p.platformFirewallState.(*pfFirewallState); ok {
		return
	}

	// pf enforcement is only meaningful when intercept mode is active -
	// without it, we have no pf anchor to add rules to.
	if dnsIntercept && p.dnsInterceptState != nil {
		p.initPFFirewall()
	} else {
		p.Info().Msg("Firewall: pf enforcement deferred until intercept mode starts")
	}
}

// initPFFirewall sets up pf-based firewall mode enforcement. Called from
// initFirewallAllowList() when running on macOS with intercept mode active.
//
// Architecture:
//   - Creates a pf table <ctrld_allowed> for dynamic IP allowlisting
//   - Registers batch change callbacks on the AllowList
//   - The actual pf anchor rules are injected via buildPFFirewallRules() which
//     is called from buildPFAnchorRules() when firewall mode is active
//
// The table approach (vs. per-IP pass rules) is critical for performance:
// pfctl table operations are O(log n) and don't require a full anchor reload.
func (p *prog) initPFFirewall() {
	state := &pfFirewallState{}
	p.platformFirewallState = state

	// Register batch callback - AllowList reaper and FlushDomain use this.
	p.allowList.SetOnBatchChange(func(added []netip.Addr, removed []netip.Addr) {
		state.mu.Lock()
		defer state.mu.Unlock()

		if len(added) > 0 {
			state.pendingAdds = append(state.pendingAdds, added...)
		}
		if len(removed) > 0 {
			state.pendingRemoves = append(state.pendingRemoves, removed...)
		}
		state.scheduleBatchFlush(p)
	})

	// Register individual change callback - Add() and Remove() use this.
	p.allowList.SetOnChange(func(ip netip.Addr, added bool) {
		state.mu.Lock()
		defer state.mu.Unlock()

		if added {
			state.pendingAdds = append(state.pendingAdds, ip)
		} else {
			state.pendingRemoves = append(state.pendingRemoves, ip)
		}
		state.scheduleBatchFlush(p)
	})

	// DNS responses may have populated the allowlist before platform callbacks
	// were registered. Bulk-load that snapshot so pf starts with the same view
	// as the in-memory allowlist.
	p.pfFirewallPopulateTable()

	// Likewise for the organization's allowed destinations, which are applied as
	// soon as the allowlist exists - before pf enforcement comes up. The table is
	// a persist table that may still hold what a previous run put in it, so mark
	// the set for a full replace rather than a delta; the reconcile retries until
	// pf has exactly the current set.
	p.markDestinationsForResync()
	p.reconcileAllowedDestinations()

	// Seed the forwarded-source snapshot with what the anchor was just built with,
	// so the first reconcile only fires on a real subsequent change.
	sources := p.forwardedSources()
	state.lastForwardedSources = sources
	state.lastForwardedKey = forwardedSourceSetKey(sources)

	// Report the effective trust set, including the configured entries. Without this
	// an admin who sets firewall_forwarded_sources has no way to confirm it took
	// effect short of reading pf rules.
	p.logForwardedSources(sources)

	p.Info().Msg("Firewall: pf table enforcement initialized")
}

// scheduleBatchFlush starts or resets the batch timer. Must be called with state.mu held.
func (s *pfFirewallState) scheduleBatchFlush(p *prog) {
	if s.batchTimer != nil {
		return
	}
	s.batchTimer = time.AfterFunc(pfFirewallBatchInterval, func() {
		s.flushBatch(p)
	})
}

// flushBatch applies accumulated pf table changes in a single pfctl call per direction.
func (s *pfFirewallState) flushBatch(p *prog) {
	s.mu.Lock()
	adds := s.pendingAdds
	removes := s.pendingRemoves
	s.pendingAdds = nil
	s.pendingRemoves = nil
	s.batchTimer = nil
	s.mu.Unlock()

	if len(adds) == 0 && len(removes) == 0 {
		return
	}

	// Collapse add/remove deltas into the current primary allowlist state. This
	// avoids leaving pf opposite the allowlist when an Add and Remove for the
	// same IP land in one batch window.
	ipsToSync := make(map[netip.Addr]struct{}, len(adds)+len(removes))
	for _, ip := range adds {
		ipsToSync[ip] = struct{}{}
	}
	for _, ip := range removes {
		ipsToSync[ip] = struct{}{}
	}

	var tableAdds, tableRemoves []string
	for ip := range ipsToSync {
		if p.allowList != nil && p.allowList.Contains(ip) {
			tableAdds = append(tableAdds, ip.String())
		} else {
			tableRemoves = append(tableRemoves, ip.String())
		}
	}

	// Apply additions.
	if len(tableAdds) > 0 {
		// pfctl -t <table> -T add accepts multiple IPs space-separated.
		args := append([]string{"-a", pfAnchorName, "-t", pfFirewallTable, "-T", "add"}, tableAdds...)
		if out, err := exec.Command("pfctl", args...).CombinedOutput(); err != nil {
			p.Warn().Err(err).Str("output", string(out)).
				Msgf("Firewall: failed to add %d IPs to pf table", len(tableAdds))
		} else {
			p.Debug().Msgf("Firewall: added %d IPs to pf table %s", len(tableAdds), pfFirewallTable)
		}
	}

	// Apply removals.
	if len(tableRemoves) > 0 {
		args := append([]string{"-a", pfAnchorName, "-t", pfFirewallTable, "-T", "delete"}, tableRemoves...)
		if out, err := exec.Command("pfctl", args...).CombinedOutput(); err != nil {
			// Not a hard error - the IP may have already been removed (e.g., by a Flush).
			p.Debug().Err(err).Str("output", string(out)).
				Msgf("Firewall: failed to remove %d IPs from pf table (may already be gone)", len(tableRemoves))
		} else {
			p.Debug().Msgf("Firewall: removed %d IPs from pf table %s", len(tableRemoves), pfFirewallTable)
		}
	}
}

// pfFirewallFlushTable removes all entries from the pf firewall table.
// Called on network changes and config reloads before the AllowList is flushed.
func (p *prog) pfFirewallFlushTable() {
	if state, ok := p.platformFirewallState.(*pfFirewallState); ok && state != nil {
		state.mu.Lock()
		if state.batchTimer != nil {
			state.batchTimer.Stop()
			state.batchTimer = nil
		}
		state.pendingAdds = nil
		state.pendingRemoves = nil
		state.mu.Unlock()
	}

	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-t", pfFirewallTable, "-T", "flush").CombinedOutput()
	if err != nil {
		p.Debug().Err(err).Str("output", string(out)).Msg("Firewall: failed to flush pf table (may not exist yet)")
	} else {
		p.Info().Msg("Firewall: flushed pf table " + pfFirewallTable)
	}
}

// pfFirewallPopulateTable bulk-loads all currently allowed IPs into the pf table.
// Called after anchor rule installation to ensure the table is populated.
func (p *prog) pfFirewallPopulateTable() {
	if p.allowList == nil {
		return
	}
	ips := p.allowList.AllowedIPs()
	if len(ips) == 0 {
		return
	}

	ipStrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}

	args := append([]string{"-a", pfAnchorName, "-t", pfFirewallTable, "-T", "add"}, ipStrs...)
	if out, err := exec.Command("pfctl", args...).CombinedOutput(); err != nil {
		p.Warn().Err(err).Str("output", string(out)).
			Msgf("Firewall: failed to populate pf table with %d IPs", len(ips))
	} else {
		p.Info().Msgf("Firewall: populated pf table with %d allowed IPs", len(ips))
	}
}

// firewallApplyExceptionsPlatform mirrors a change to the organization's Allowed
// Destination IP list into the pf exception table, reporting whether pf took it.
//
// An error - including "pf enforcement is not up yet", because the anchor that
// declares the table has not been loaded and pfctl would fail - leaves the
// caller's applied snapshot unadvanced, so the same delta is retried later.
func (p *prog) firewallApplyExceptionsPlatform(added, removed []netip.Prefix) error {
	if state, ok := p.platformFirewallState.(*pfFirewallState); !ok || state == nil {
		return errors.New("pf firewall enforcement is not initialized")
	}
	return errors.Join(
		p.pfFirewallExceptionTableOp("add", prefixStrings(added)),
		p.pfFirewallExceptionTableOp("delete", prefixStrings(removed)),
	)
}

const (
	// pfExceptionTableOpTimeout bounds one pfctl call against the exception table.
	// reconcileDestinations holds destinationsMu across the mirror, and both the
	// configuration refresh loop and Firewall Mode teardown contend on that lock,
	// so a pfctl that never returns would stall refresh detection of custom_config
	// and pin changes along with the teardown itself. Generous enough that a busy
	// pf never trips it, short enough that a wedged one is not indefinite.
	pfExceptionTableOpTimeout = 30 * time.Second

	// pfExceptionTableOpChunk caps the addresses handed to one pfctl invocation.
	// The organization's list is API-supplied and unbounded, and every entry
	// becomes an argv element, so a long enough list would exceed ARG_MAX and fail
	// as a whole rather than being applied.
	pfExceptionTableOpChunk = 500
)

// pfFirewallExceptionTableOp runs one pfctl table operation ("add", "delete" or
// "replace") against the exception table. pf table entries are addressed exactly,
// so deleting a network never disturbs a resolved host address inside it.
//
// Long lists are split across invocations. Only the first chunk carries the
// caller's operation: a chunked "replace" would otherwise leave the table holding
// the last chunk alone, each call having discarded what the previous one
// installed, so the chunks after it add to what the replace established.
func (p *prog) pfFirewallExceptionTableOp(op string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}
	for _, chunk := range pfExceptionTableChunks(op, entries) {
		if err := p.pfFirewallExceptionTableCall(chunk.op, chunk.entries); err != nil {
			return err
		}
	}
	return nil
}

// pfExceptionTableChunk is one pfctl invocation's share of a table operation.
type pfExceptionTableChunk struct {
	op      string
	entries []string
}

// pfExceptionTableChunks splits a table operation into invocation-sized pieces.
// Only the first piece carries the requested operation; the rest add, so that a
// split "replace" installs the whole set instead of each piece discarding what
// the previous one installed. "add" and "delete" are per-entry operations, so
// splitting them changes nothing.
func pfExceptionTableChunks(op string, entries []string) []pfExceptionTableChunk {
	var chunks []pfExceptionTableChunk
	for start := 0; start < len(entries); start += pfExceptionTableOpChunk {
		end := min(start+pfExceptionTableOpChunk, len(entries))
		chunkOp := op
		// Only a replace changes after the first chunk. "add" and "delete" are
		// per-entry, and rewriting a later delete chunk as an add would put back
		// exactly the destinations the organization withdrew.
		if op == "replace" && start > 0 {
			chunkOp = "add"
		}
		chunks = append(chunks, pfExceptionTableChunk{op: chunkOp, entries: entries[start:end]})
	}
	return chunks
}

// pfFirewallExceptionTableCall runs a single pfctl invocation for one chunk.
func (p *prog) pfFirewallExceptionTableCall(op string, entries []string) error {
	out, err := pfExceptionTableCommand(op, entries)
	if err != nil {
		// A delete against a table that does not exist has already achieved what it
		// asked for: with no table there is nothing permitting the entry. Treating
		// it as a failure would keep the withdrawal pending forever, since no later
		// retry can make an absent table deletable. This matches the WFP mirror,
		// which tolerates FWP_E_FILTER_NOT_FOUND on delete for the same reason.
		if op == "delete" && pfTableMissing(out) {
			p.Debug().Int("entries", len(entries)).
				Msgf("Firewall: pf table %s does not exist; the allowed destinations it would have held are already not permitted", pfFirewallExceptionTable)
			return nil
		}
		return fmt.Errorf("pfctl -t %s -T %s (%d entries): %w (output: %s)",
			pfFirewallExceptionTable, op, len(entries), err, strings.TrimSpace(string(out)))
	}
	p.Debug().Strs("entries", entries).
		Msgf("Firewall: %s %d allowed destinations in pf table %s", pfTableOpPastTense(op), len(entries), pfFirewallExceptionTable)
	return nil
}

// pfExceptionTableCommand runs one pfctl exception-table call under a timeout.
func pfExceptionTableCommand(op string, entries []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfExceptionTableOpTimeout)
	defer cancel()
	args := append([]string{"-a", pfAnchorName, "-t", pfFirewallExceptionTable, "-T", op}, entries...)
	return exec.CommandContext(ctx, "pfctl", args...).CombinedOutput()
}

// pfTableMissing reports whether pfctl failed because the table is not loaded.
func pfTableMissing(out []byte) bool {
	return strings.Contains(strings.ToLower(string(out)), "table does not exist")
}

// pfTableOpPastTense renders a pfctl table operation for log messages.
func pfTableOpPastTense(op string) string {
	switch op {
	case "delete":
		return "removed"
	case "replace":
		return "installed"
	default:
		return "added"
	}
}

// firewallReplaceExceptionsPlatform makes the pf exception table hold exactly
// desired, whatever it held before.
//
// This is what runs when pf enforcement starts, and it must succeed before the
// applied snapshot is established: the table is a persist table that outlives the
// process, so a destination the organization withdrew while ctrld was stopped is
// still in it. Reporting failure is the point - a discarded error here would
// leave that entry bypassing Firewall Mode for the life of the process, with
// nothing pending to say so.
func (p *prog) firewallReplaceExceptionsPlatform(desired []netip.Prefix) error {
	if state, ok := p.platformFirewallState.(*pfFirewallState); !ok || state == nil {
		return errors.New("pf firewall enforcement is not initialized")
	}
	entries := prefixStrings(desired)
	if len(entries) == 0 {
		// pfctl -T replace needs at least one address; emptying is a flush.
		out, err := pfExceptionTableCommand("flush", nil)
		if err != nil {
			if pfTableMissing(out) {
				p.Debug().Msgf("Firewall: pf table %s does not exist; nothing is permitted through it", pfFirewallExceptionTable)
				return nil
			}
			return fmt.Errorf("pfctl -t %s -T flush: %w (output: %s)",
				pfFirewallExceptionTable, err, strings.TrimSpace(string(out)))
		}
		p.Debug().Msgf("Firewall: emptied pf table %s", pfFirewallExceptionTable)
		return nil
	}
	return p.pfFirewallExceptionTableOp("replace", entries)
}

// buildPFFirewallRules generates the pf rules for firewall mode enforcement.
// These rules are appended to the anchor by buildPFAnchorRules() when firewall
// mode is active.
//
// The strategy is:
//   - Define table <ctrld_allowed> (dynamically populated via pfctl -T add/delete)
//   - Block all outbound traffic by default (after DNS intercept rules)
//   - Pass outbound to IPs in <ctrld_allowed>
//   - Pass outbound from ctrld's group (already handled by blanket exemption)
//   - Pass loopback, link-local, multicast (already handled by permanent allowlist,
//     but explicit pf rules prevent kernel-level blocking before our check)
//
// IMPORTANT: These rules must come AFTER the DNS intercept rules in the anchor
// so that DNS itself still works (DNS is how IPs get into the allowlist).
func buildPFFirewallRules() string {
	var rules strings.Builder

	rules.WriteString("\n# --- Firewall Mode: DNS-resolved IP allowlist enforcement ---\n")
	rules.WriteString("# Only IPs resolved by ctrld are allowed for outbound connections.\n")
	rules.WriteString("# Table is dynamically populated from DNS responses.\n\n")

	// Declare the tables. pfctl -T add/delete operates on these dynamically.
	fmt.Fprintf(&rules, "table <%s> persist\n", pfFirewallTable)
	fmt.Fprintf(&rules, "table <%s> persist\n\n", pfFirewallExceptionTable)

	// Pass traffic to allowed IPs (both IPv4 and IPv6).
	rules.WriteString("# Allow outbound to DNS-resolved IPs.\n")
	fmt.Fprintf(&rules, "pass out quick inet proto { tcp, udp } from any to <%s>\n", pfFirewallTable)
	fmt.Fprintf(&rules, "pass out quick inet6 proto { tcp, udp } from any to <%s>\n\n", pfFirewallTable)

	// Pass traffic to the organization's allowed destinations. These are reachable
	// by literal IP, with no DNS lookup for ctrld to observe, which is the whole
	// point of the list; the table is populated from the API's effective set.
	rules.WriteString("# Allow outbound to organization allowed destination IPs.\n")
	fmt.Fprintf(&rules, "pass out quick inet proto { tcp, udp } from any to <%s>\n", pfFirewallExceptionTable)
	fmt.Fprintf(&rules, "pass out quick inet6 proto { tcp, udp } from any to <%s>\n\n", pfFirewallExceptionTable)

	// Allow ICMP/ICMPv6 - needed for path MTU discovery, ping, etc.
	rules.WriteString("# Allow ICMP (path MTU discovery, ping, etc.)\n")
	rules.WriteString("pass out quick inet proto icmp\n")
	rules.WriteString("pass out quick inet6 proto icmp6\n\n")

	// Allow all loopback traffic (safety net - permanent allowlist covers this too).
	rules.WriteString("# Allow all loopback traffic.\n")
	rules.WriteString("pass out quick on lo0\n")
	rules.WriteString("pass in quick on lo0\n\n")

	// Allow RFC1918 and link-local - these are in the permanent allowlist but
	// explicit pf rules prevent the block rule below from catching them.
	rules.WriteString("# Allow private/link-local ranges (LAN, printers, NAS, mDNS, DHCP).\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 10.0.0.0/8\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 172.16.0.0/12\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 192.168.0.0/16\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 169.254.0.0/16\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 100.64.0.0/10\n")
	rules.WriteString("pass out quick inet6 proto { tcp, udp } from any to fe80::/10\n\n")

	// Allow multicast (mDNS, SSDP, etc.).
	rules.WriteString("# Allow multicast (mDNS, SSDP, etc.).\n")
	rules.WriteString("pass out quick inet proto { tcp, udp } from any to 224.0.0.0/4\n")
	rules.WriteString("pass out quick inet6 proto { tcp, udp } from any to ff00::/8\n\n")

	// Allow DHCP (UDP 67/68) - needed for network configuration.
	rules.WriteString("# Allow DHCP.\n")
	rules.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n\n")

	// Block everything else. This is the enforcement rule.
	// "block return" sends TCP RST / ICMP unreachable so apps fail fast instead of timing out.
	rules.WriteString("# Block all other outbound traffic (IPs not resolved by ctrld).\n")
	rules.WriteString("block return out quick inet proto { tcp, udp } from any to any\n")
	rules.WriteString("block return out quick inet6 proto { tcp, udp } from any to any\n")

	return rules.String()
}

// forwardedSource is a trusted VM/container source subnet. iface is the ingress
// interface for an auto-detected source, used to scope its pf rules to that
// interface so unrelated same-subnet traffic on other interfaces is unaffected.
// iface is empty for an operator-configured source, which matches on the source
// CIDR alone — an explicit opt-in the admin is responsible for.
type forwardedSource struct {
	prefix netip.Prefix
	iface  string
}

// firewallForwardedSources parses the operator-configured forwarded-workload
// source subnets (service.firewall_forwarded_sources), dropping - with a warning -
// any entry that is not a valid CIDR, or is not IPv4, so one bad line never voids the
// whole set. These augment auto-detection (see forwardedSources) and are the supported
// way to trust generic bridge* stacks (Multipass, Docker Desktop).
//
// The IPv4 restriction is not cosmetic: forwarded DNS can only be redirected to
// ctrld's IPv4 intercept listener, and an IPv6 source would otherwise produce pf rules
// whose address family contradicts their source literal, which makes pfctl reject the
// entire anchor and take DNS interception down with it.
func (p *prog) firewallForwardedSources() []forwardedSource {
	sources, rejected := parseForwardedSourceConfig(p.cfg.Service.FirewallForwardedSources)
	p.warnRejectedForwardedSources(rejected)
	return sources
}

// rejectedForwardedSource is a configured entry that could not be used, with the
// reason to report to the operator.
type rejectedForwardedSource struct {
	value  string
	reason string
}

// parseForwardedSourceConfig parses configured entries, returning the usable sources
// and the rejected ones. It is pure and silent: callers decide when a rejection is
// worth logging, because this runs on every anchor build and every watchdog tick.
func parseForwardedSourceConfig(raw []string) ([]forwardedSource, []rejectedForwardedSource) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]forwardedSource, 0, len(raw))
	var rejected []rejectedForwardedSource
	for _, s := range raw {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			rejected = append(rejected, rejectedForwardedSource{
				value:  s,
				reason: "not a valid CIDR (want e.g. 192.168.64.0/24): " + err.Error(),
			})
			continue
		}
		if !pfx.Addr().Is4() {
			rejected = append(rejected, rejectedForwardedSource{
				value:  s,
				reason: "not IPv4 - forwarded-workload DNS interception is IPv4-only (ctrld's intercept listener is IPv4)",
			})
			continue
		}
		out = append(out, forwardedSource{prefix: pfx.Masked()})
	}
	return out, rejected
}

// warnRejectedForwardedSources reports unusable configured entries, but only when the
// set of rejections changes (see forwardedSourceWarnTracker).
func (p *prog) warnRejectedForwardedSources(rejected []rejectedForwardedSource) {
	key := rejectedForwardedSourcesKey(rejected)

	forwardedSourceWarnTracker.mu.Lock()
	unchanged := forwardedSourceWarnTracker.key == key
	forwardedSourceWarnTracker.key = key
	forwardedSourceWarnTracker.mu.Unlock()

	if unchanged {
		return
	}
	for _, r := range rejected {
		p.Warn().Str("value", r.value).
			Msgf("Firewall: ignoring firewall_forwarded_sources entry - %s", r.reason)
	}
}

// rejectedForwardedSourcesKey returns an order-independent signature of a rejection
// set, so re-parsing an unchanged config is recognised as nothing new to report.
func rejectedForwardedSourcesKey(rejected []rejectedForwardedSource) string {
	if len(rejected) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rejected))
	for _, r := range rejected {
		parts = append(parts, r.value+"|"+r.reason)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// detectForwardedSources auto-discovers VM/NAT networks on the host so the common
// case works with no configuration.
//
// An interface qualifies only if it is up, carries an RFC1918 IPv4 network, AND its
// VM ownership can be proven one of two ways:
//
//   - its own name is vendor-specific (hypervisorVMNetPrefixes): Parallels, legacy
//     Fusion, VirtualBox host-only;
//   - it is a bridge whose member list contains a vendor-specific interface
//     (bridgeHasVMMember): every vmnet.framework stack, where the address lives on
//     bridge10x and the vendor-named vmenet* member has none.
//
// Ownership proof is the security boundary: a bridge is trusted for what is bridged
// into it, never for its name. The RFC1918 filter is the second boundary - a stack
// presenting a public range is never auto-trusted. Each detected source keeps its
// ingress interface so its pf rules stay scoped to it.
//
// Addresses are checked before membership so the ifconfig call is only made for a
// bridge that could actually qualify; a Thunderbolt bridge with no RFC1918 address
// costs nothing.
func (p *prog) detectForwardedSources() []forwardedSource {
	ifaces, err := net.Interfaces()
	if err != nil {
		p.Warn().Err(err).Msg("Firewall: could not enumerate interfaces for forwarded-source detection")
		return nil
	}
	var out []forwardedSource
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		sources, reason := forwardedSourcesForIface(ifi.Name, addrs, bridgeMembersFn)
		for _, src := range sources {
			out = append(out, src)
			// Debug, not Info: detection re-runs on every anchor build. The effective
			// set is reported once by logForwardedSources at init and on every change.
			p.Debug().Str("iface", src.iface).Str("subnet", src.prefix.String()).Str("reason", reason).
				Msg("Firewall: auto-detected VM/container network for forwarded DNS")
		}
	}
	return out
}

// forwardedSourcesForIface decides whether one up interface is an auto-trusted
// forwarded-workload source, and returns its subnets plus why it qualified.
//
// Split out from interface enumeration so the trust decision - which is a security
// boundary - is testable against synthetic interfaces, including the cases that must
// NOT qualify: a Thunderbolt bridge, a public-range VM network, an address-less
// vendor interface.
//
// members is only consulted for a bridge that already has an RFC1918 IPv4 address, so
// no subprocess runs for the address-less or public bridges on a typical host.
func forwardedSourcesForIface(name string, addrs []net.Addr, members func(string) []string) ([]forwardedSource, string) {
	vendorNamed := isHypervisorVMNetIface(name)
	if !vendorNamed && !isBridgeIface(name) {
		return nil, ""
	}
	prefixes := privateIPv4Prefixes(addrs)
	if len(prefixes) == 0 {
		return nil, ""
	}
	reason := "vendor VM interface"
	if !vendorNamed {
		mem := members(name)
		if !bridgeHasVMMember(mem) {
			return nil, ""
		}
		reason = "bridge with VM member " + strings.Join(vmMembers(mem), ",")
	}
	out := make([]forwardedSource, 0, len(prefixes))
	for _, pfx := range prefixes {
		out = append(out, forwardedSource{prefix: pfx, iface: name})
	}
	return out, reason
}

// privateIPv4Prefixes returns the masked RFC1918 IPv4 networks among addrs, skipping
// public and IPv6 addresses.
func privateIPv4Prefixes(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		pfx, err := netip.ParsePrefix(ipnet.String())
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		if !pfx.Addr().Is4() || !pfx.Addr().IsPrivate() {
			continue
		}
		out = append(out, pfx)
	}
	return out
}

// vmMembers returns the vendor VM interfaces among a bridge's members, for logging
// which member made the bridge trusted.
func vmMembers(members []string) []string {
	var out []string
	for _, m := range members {
		if isHypervisorVMNetIface(m) {
			out = append(out, m)
		}
	}
	return out
}

// forwardedSources returns the effective trusted set: auto-detected vendor VM
// networks UNION operator-configured subnets, de-duplicated by prefix (a subnet
// that is both auto-detected and configured keeps the interface-scoped
// auto-detected form). Config augments auto-detection; it never disables it.
func (p *prog) forwardedSources() []forwardedSource {
	var out []forwardedSource
	seen := make(map[netip.Prefix]struct{})
	for _, group := range [][]forwardedSource{
		p.detectForwardedSources(),
		p.firewallForwardedSources(),
	} {
		for _, src := range group {
			if _, dup := seen[src.prefix]; dup {
				continue
			}
			seen[src.prefix] = struct{}{}
			out = append(out, src)
		}
	}
	return out
}

// forwardedSourceSetKey returns a deterministic, order-independent signature of a
// forwarded-source set. reconcileForwardedSources compares it across time to detect
// when VM/container interfaces appear or disappear.
func forwardedSourceSetKey(sources []forwardedSource) string {
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, s.iface+"|"+s.prefix.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// currentForwardedSources returns the effective forwarded-source set, or nil when
// Firewall Mode is off.
//
// The gate matters because detection is not free: it enumerates interfaces, execs
// ifconfig for each candidate bridge, and re-parses config. Those rules are only ever
// emitted in firewall mode, so doing any of it with firewall mode off is pure waste -
// and it would report unusable config entries on a path where nothing wants them.
// Anchor rebuilds happen on every tunnel change, watchdog restore and VPN DNS update
// regardless of firewall mode, so this is the difference between zero work and work on
// every one of them.
func (p *prog) currentForwardedSources() []forwardedSource {
	if !p.firewallModeEnabled() {
		return nil
	}
	return p.forwardedSources()
}

// buildPFForwardedSourceRulesFor generates the pf rules that make the given
// VM/container (forwarded/NATed) source subnets first-class Firewall Mode clients
// WITHOUT an interface-wide bypass. Returns "" for an empty input so anchor
// behavior is unchanged when there are no sources.
//
// For each source subnet:
//
//   - Plaintext DNS (port 53) is force-routed through ctrld's loopback listener
//     (route-to lo0, which then hits the existing rdr-on-lo0 redirect). ctrld
//     therefore observes and policy-enforces every guest resolution, and the
//     resolved IP lands in <ctrld_allowed>. The guest's subsequent egress to that
//     IP is permitted by the existing "pass out ... to <ctrld_allowed>" rule: NAT
//     rewrites the guest source to the host, which that rule's "from any" covers.
//   - DoT (port 853) to any resolver is blocked so the guest cannot swap in an
//     alternate encrypted resolver to escape policy. DoH over 443 is
//     indistinguishable from ordinary HTTPS and is a documented limitation.
//
// Auto-detected sources carry their ingress interface and are scoped with
// "on <iface>", so an unrelated interface on the same private range is never
// affected. Configured sources (admin opt-in) match on the source CIDR alone.
// All matches are on the pre-NAT guest source (inbound): after NAT the source is
// the host and could no longer be told apart. This is an explicit, per-subnet
// trust boundary - a direct public IP the guest never resolved through ctrld stays
// blocked, so the guest cannot bypass Control D policy.
//
// IPv4 only, and strictly per address family: ctrld's intercept listener is IPv4, so
// IPv6 guest DNS cannot be redirected here - the anchor's existing
// "block out ... inet6 ... port 53" rule forces guests to fall back to interceptable
// IPv4 DNS, and guest IPv6 egress to an alternate resolver is covered by the blanket
// IPv6 block plus the fact that such a resolver never enters <ctrld_allowed>.
// Consequently only IPv4 sources produce rules, and each rule's address family
// matches its source literal: pf rejects a whole anchor over a single
// "inet6 ... from 192.168.x.0/24" mismatch, which would take DNS interception down
// with it. Non-IPv4 sources are skipped here as a backstop; firewallForwardedSources
// already drops them at parse time with a warning.
func buildPFForwardedSourceRulesFor(sources []forwardedSource, listenerIP string) string {
	sources = ipv4ForwardedSources(sources)
	if len(sources) == 0 {
		return ""
	}

	var rules strings.Builder
	rules.WriteString("\n# --- Firewall Mode: forwarded workload (VM/container) DNS interception ---\n")
	rules.WriteString("# VM/container source subnets (auto-detected vendor VM networks + configured).\n")
	rules.WriteString("# Their DNS is forced through ctrld so guest resolutions are policy-enforced and\n")
	fmt.Fprintf(&rules, "# populate <%s>; egress to allowed IPs is then permitted by the allowlist rule\n", pfFirewallTable)
	rules.WriteString("# below. Auto-detected sources are scoped to their ingress interface; this is an\n")
	rules.WriteString("# explicit, per-subnet trust boundary - NOT an interface-wide permit.\n\n")

	for _, src := range sources {
		cidr := src.prefix.String()
		on := ""
		label := "configured (source-CIDR scope)"
		if src.iface != "" {
			on = "on " + src.iface + " "
			label = "auto-detected on " + src.iface
		}
		fmt.Fprintf(&rules, "# %s - %s\n", cidr, label)
		// Force guest plaintext DNS (port 53) onto loopback, where the existing
		// rdr-on-lo0 rule redirects it to ctrld. Matched inbound (pre-NAT); "quick"
		// so it wins over the blanket block that buildPFFirewallRules appends after.
		fmt.Fprintf(&rules, "pass in quick %sroute-to lo0 inet proto udp from %s to ! %s port 53\n", on, cidr, listenerIP)
		fmt.Fprintf(&rules, "pass in quick %sroute-to lo0 inet proto tcp from %s to ! %s port 53\n", on, cidr, listenerIP)
		// Block DoT so the guest cannot escape ctrld via an alternate encrypted
		// resolver. DoH over 443 is indistinguishable from HTTPS - documented limitation.
		// inet only: the source literal is IPv4, and pf refuses to load an anchor
		// containing an inet6 rule with an IPv4 source.
		fmt.Fprintf(&rules, "block return in quick %sinet proto { tcp, udp } from %s to any port 853\n\n", on, cidr)
	}

	return rules.String()
}

// ipv4ForwardedSources returns the IPv4 subset of sources. Forwarded-workload DNS
// interception is IPv4-only (the intercept listener is IPv4), and every emitted rule
// must match its source's address family or pfctl rejects the entire anchor.
func ipv4ForwardedSources(sources []forwardedSource) []forwardedSource {
	out := make([]forwardedSource, 0, len(sources))
	for _, src := range sources {
		if src.prefix.Addr().Is4() {
			out = append(out, src)
		}
	}
	return out
}

// reconcileForwardedSources rebuilds the pf anchor when the effective forwarded-
// source set (auto-detected VM networks + configured) has changed since the last
// build, and drops the pf states of every subnet whose trust changed.
//
// VM/container interfaces appear and disappear at runtime (guest start/stop) and no
// existing path rebuilds an otherwise-intact anchor for that: ensurePFAnchorActive()
// returns early while the rules still exist, checkTunnelInterfaceChanges() tracks
// only tunnel interfaces, and pfInterceptMonitor() rebuilds only after the host
// interception probe fails. Without this, a guest started after ctrld would never be
// trusted, and a stopped guest's subnet would stay trusted until an unrelated
// rebuild. Invoked from the network-change paths and, as a time bound when no event
// fires, from the pf watchdog tick.
//
// A reload failure is not latched: the applied snapshot only advances once pf has
// actually accepted the new anchor, so the next reconcile (at the latest the next
// watchdog tick) retries the same change instead of treating it as done.
func (p *prog) reconcileForwardedSources() {
	if !p.firewallModeEnabled() || p.dnsInterceptState == nil {
		return
	}
	state, ok := p.platformFirewallState.(*pfFirewallState)
	if !ok || state == nil {
		return
	}
	sources := p.forwardedSources()
	reload := func() error { return p.reloadForwardedSourceAnchor(sources) }
	gained, lost, changed, err := state.applyForwardedSourceChange(sources, reload)
	if !changed {
		return
	}
	if err != nil {
		p.Warn().Err(err).Strs("gained_trust", prefixStrings(gained)).Strs("lost_trust", prefixStrings(lost)).
			Msg("Firewall: forwarded-source set changed but the pf anchor reload failed — keeping the previously applied set so the next reconcile retries")
		return
	}
	p.Info().Strs("gained_trust", prefixStrings(gained)).Strs("lost_trust", prefixStrings(lost)).
		Msg("Firewall: forwarded-source set changed (VM/container start/stop), pf anchor rebuilt")
	// Restate the whole effective set, so one log line always answers "what is trusted
	// right now" without replaying every earlier transition.
	p.logForwardedSources(sources)
	// Rules only govern new states, so kill the states of the affected subnets:
	// a subnet that lost trust must stop using states created while it was trusted,
	// and one that just gained it must have its pre-existing (un-intercepted) DNS
	// states re-evaluated instead of running until they expire. The guest simply
	// re-establishes the connections under the new rules. Only reached after a
	// successful load - killing states against the old anchor would just have them
	// recreated under the very rules the change was meant to replace.
	p.killForwardedSourceStates(append(gained, lost...))
}

// applyForwardedSourceChange performs one reconcile step: compare cur against the
// last applied forwarded-source set and, when it differs, install it via reload.
// It reports which subnets gained and lost trust (trust identity is (subnet,
// interface scope), so a subnet that stays but changes scope appears in both lists),
// whether there was anything to do at all, and reload's error.
//
// The applied snapshot advances ONLY after reload returns nil. A failed write or
// pfctl load therefore leaves the previous set recorded, so the running anchor and
// the snapshot cannot diverge and the change is retried on the next reconcile rather
// than silently dropped. The whole check-reload-record sequence is serialized so
// concurrent callers (watchdog tick vs. network change) cannot both rebuild or
// interleave their snapshot updates.
//
// Split out from reconcileForwardedSources so the guest start/stop lifecycle and the
// failure-then-retry path are deterministically testable without pf or a hypervisor.
func (s *pfFirewallState) applyForwardedSourceChange(cur []forwardedSource, reload func() error) (gained, lost []netip.Prefix, changed bool, err error) {
	s.applyForwardedMu.Lock()
	defer s.applyForwardedMu.Unlock()

	key := forwardedSourceSetKey(cur)
	s.mu.Lock()
	applied, appliedKey := s.lastForwardedSources, s.lastForwardedKey
	s.mu.Unlock()

	if key == appliedKey {
		return nil, nil, false, nil
	}
	gained = forwardedSubnetsNotIn(cur, applied)
	lost = forwardedSubnetsNotIn(applied, cur)

	if err := reload(); err != nil {
		return gained, lost, true, err
	}

	s.mu.Lock()
	s.lastForwardedSources = cur
	s.lastForwardedKey = key
	s.mu.Unlock()
	return gained, lost, true, nil
}

// forwardedSubnetsNotIn returns the subnets of a whose exact trust entry (subnet +
// interface scope) is absent from b, de-duplicated.
func forwardedSubnetsNotIn(a, b []forwardedSource) []netip.Prefix {
	inB := make(map[forwardedSource]struct{}, len(b))
	for _, src := range b {
		inB[src] = struct{}{}
	}
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{}, len(a))
	for _, src := range a {
		if _, ok := inB[src]; ok {
			continue
		}
		if _, dup := seen[src.prefix]; dup {
			continue
		}
		seen[src.prefix] = struct{}{}
		out = append(out, src.prefix)
	}
	return out
}

// forwardedSourceDescriptions renders the effective trust set for logging, naming each
// subnet's origin so an admin can tell an auto-detected VM network (and the interface
// its rules are scoped to) from an entry they configured.
func forwardedSourceDescriptions(sources []forwardedSource) []string {
	out := make([]string, 0, len(sources))
	for _, src := range sources {
		if src.iface != "" {
			out = append(out, src.prefix.String()+" (auto-detected on "+src.iface+")")
			continue
		}
		out = append(out, src.prefix.String()+" (configured)")
	}
	return out
}

// logForwardedSources reports the effective forwarded-workload trust set. Configured
// entries were previously invisible in the log - only auto-detection said anything -
// so an admin had no way to confirm firewall_forwarded_sources took effect. The empty
// case is logged too, with what to do about it, because "no guest DNS interception"
// looks identical to "feature silently did nothing".
func (p *prog) logForwardedSources(sources []forwardedSource) {
	if len(sources) == 0 {
		p.Info().Msg("Firewall: no forwarded-workload (VM/container) sources — guest DNS is not intercepted. " +
			"Auto-detection needs an up interface with an RFC1918 IPv4 address that is either vendor-named " +
			"(vnic*, vboxnet*, vmnet*) or a bridge with a VM member (vmenet*); anything else must be listed " +
			"in service.firewall_forwarded_sources")
		return
	}
	p.Info().Int("count", len(sources)).Strs("sources", forwardedSourceDescriptions(sources)).
		Msg("Firewall: forwarded-workload (VM/container) DNS interception active for these source subnets")
}

// killForwardedSourceStates drops the pf state entries sourced from the given
// subnets. Targeted (pfctl -k <network>) rather than a global state flush, so a
// guest starting or stopping never resets unrelated host connections.
func (p *prog) killForwardedSourceStates(prefixes []netip.Prefix) {
	for _, pfx := range prefixes {
		out, err := exec.Command("pfctl", "-k", pfx.String()).CombinedOutput()
		if err != nil {
			// Not a hard error - most often there simply are no matching states.
			p.Debug().Err(err).Str("subnet", pfx.String()).Str("output", strings.TrimSpace(string(out))).
				Msg("Firewall: could not kill pf states for changed forwarded source")
			continue
		}
		p.Info().Str("subnet", pfx.String()).
			Msg("Firewall: killed pf states for changed forwarded source")
	}
}

// recordAppliedForwardedSources records sources as the set pf is now enforcing.
//
// Called by the rebuild paths that are not the forwarded-source reconcile itself
// (tunnel change, watchdog restore, VPN DNS exemptions, forced reload, startup): each
// of those installs a full anchor that already contains the current set, so without
// this the next reconcile would compare against a stale snapshot and redo the work.
//
// Takes applyForwardedMu so a record cannot land in the middle of a reconcile's
// compare-reload-record sequence and be overwritten by it, or overwrite it.
func (p *prog) recordAppliedForwardedSources(sources []forwardedSource) {
	state, ok := p.platformFirewallState.(*pfFirewallState)
	if !ok || state == nil {
		return
	}
	state.applyForwardedMu.Lock()
	defer state.applyForwardedMu.Unlock()

	state.mu.Lock()
	state.lastForwardedSources = sources
	state.lastForwardedKey = forwardedSourceSetKey(sources)
	state.mu.Unlock()
}

// reloadForwardedSourceAnchor rebuilds and reloads the ctrld pf anchor so the given
// forwarded-source rules take effect. Mirrors the anchor reload used by the intercept
// watchdog, but reports failure to the caller: whether pf actually accepted the anchor
// decides whether the new source set may be recorded as applied.
//
// The set is passed in rather than re-detected, so what gets loaded is exactly what
// the caller compared and will record. Re-detecting here could install a set that
// differs from the recorded snapshot if an interface appeared in between.
func (p *prog) reloadForwardedSourceAnchor(sources []forwardedSource) error {
	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRulesWith(vpnExemptions, sources)
	if err := writePFAnchorFile(rulesStr); err != nil {
		return fmt.Errorf("write pf anchor %s: %w", pfAnchorFile, err)
	}
	if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput(); err != nil {
		return fmt.Errorf("load pf anchor %s: %w (output: %s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

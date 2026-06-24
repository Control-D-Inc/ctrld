//go:build darwin

package cli

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
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
}

const (
	// pfFirewallTable is the pf table name for dynamically-allowed IPs.
	pfFirewallTable = "ctrld_allowed"

	// pfFirewallBatchInterval is the accumulation window for batching pf table updates.
	// Short enough for responsiveness, long enough to avoid per-DNS-response pfctl calls.
	pfFirewallBatchInterval = 200 * time.Millisecond
)

// firewallFlushPlatform flushes the pf table on macOS.
func (p *prog) firewallFlushPlatform() {
	p.pfFirewallFlushTable()
}

// shutdownPlatformFirewall removes macOS firewall-mode dynamic state. The pf
// anchor itself is rebuilt by DNS intercept without firewall rules once
// p.allowList is nil.
func (p *prog) shutdownPlatformFirewall() {
	p.pfFirewallFlushTable()

	if p.dnsInterceptState == nil {
		return
	}

	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRules(vpnExemptions)
	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
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

	// pf enforcement is only meaningful when intercept mode is active —
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

	// Register batch callback — AllowList reaper and FlushDomain use this.
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

	// Register individual change callback — Add() and Remove() use this.
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
			// Not a hard error — the IP may have already been removed (e.g., by a Flush).
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

	// Declare the table. pfctl -T add/delete operates on this table dynamically.
	fmt.Fprintf(&rules, "table <%s> persist\n\n", pfFirewallTable)

	// Pass traffic to allowed IPs (both IPv4 and IPv6).
	rules.WriteString("# Allow outbound to DNS-resolved IPs.\n")
	fmt.Fprintf(&rules, "pass out quick inet proto { tcp, udp } from any to <%s>\n", pfFirewallTable)
	fmt.Fprintf(&rules, "pass out quick inet6 proto { tcp, udp } from any to <%s>\n\n", pfFirewallTable)

	// Allow ICMP/ICMPv6 — needed for path MTU discovery, ping, etc.
	rules.WriteString("# Allow ICMP (path MTU discovery, ping, etc.)\n")
	rules.WriteString("pass out quick inet proto icmp\n")
	rules.WriteString("pass out quick inet6 proto icmp6\n\n")

	// Allow all loopback traffic (safety net — permanent allowlist covers this too).
	rules.WriteString("# Allow all loopback traffic.\n")
	rules.WriteString("pass out quick on lo0\n")
	rules.WriteString("pass in quick on lo0\n\n")

	// Allow RFC1918 and link-local — these are in the permanent allowlist but
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

	// Allow DHCP (UDP 67/68) — needed for network configuration.
	rules.WriteString("# Allow DHCP.\n")
	rules.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n\n")

	// Block everything else. This is the enforcement rule.
	// "block return" sends TCP RST / ICMP unreachable so apps fail fast instead of timing out.
	rules.WriteString("# Block all other outbound traffic (IPs not resolved by ctrld).\n")
	rules.WriteString("block return out quick inet proto { tcp, udp } from any to any\n")
	rules.WriteString("block return out quick inet6 proto { tcp, udp } from any to any\n")

	return rules.String()
}

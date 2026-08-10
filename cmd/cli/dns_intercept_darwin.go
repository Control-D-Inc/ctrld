//go:build darwin

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// skipInitialDNSReset is Windows-only; macOS keeps the normal adapter cleanup
// before installing its pf redirect.
func (p *prog) skipInitialDNSReset() bool { return false }

const (
	// pfWatchdogInterval is how often the periodic pf watchdog checks
	// that our anchor references are still present in the running ruleset.
	pfWatchdogInterval = 30 * time.Second

	// pfConsecutiveMissThreshold is the number of consecutive watchdog cycles
	// where the anchor was found missing before escalating to ERROR level.
	// This indicates something is persistently fighting our pf rules.
	pfConsecutiveMissThreshold = 3

	// pfAnchorRecheckDelay is how long to wait after a network change before
	// performing a second pf anchor check. This catches race conditions where
	// another program (e.g., Windscribe desktop) clears pf rules slightly
	// after our network change handler runs.
	pfAnchorRecheckDelay = 2 * time.Second

	// pfAnchorRecheckDelayLong is a second, longer delayed re-check after network
	// changes. Some VPNs (e.g., Windscribe) take 3-4s to fully tear down their pf
	// rules and DNS settings on disconnect. This catches slower teardowns that the
	// 2s re-check misses.
	pfAnchorRecheckDelayLong = 4 * time.Second

	// pfExecFailureBackoff suppresses repeated pfctl/scutil checks briefly after
	// macOS reports local resource exhaustion. Without this, network-change storms
	// can turn a pf ruleset race into a fork/file-descriptor exhaustion loop.
	pfExecFailureBackoff = 5 * time.Second

	// pfStabilizationMaxWait bounds the total period ordinary repair can be
	// suppressed if PF never becomes stable or pfctl keeps failing.
	pfStabilizationMaxWait = 90 * time.Second

	// pfIgnoredChangeReconcileInterval bounds leading-edge pf/VPN-DNS work
	// during continuous ignored network-change storms. The 2s/4s delayed checks
	// still provide trailing reconciliation once the storm stops.
	pfIgnoredChangeReconcileInterval = pfAnchorRecheckDelayLong

	// pfVPNInterfacePrefixes lists interface name prefixes that indicate VPN/tunnel
	// interfaces on macOS. Used to add interface-specific DNS intercept rules so that
	// VPN software with "pass out quick on <iface>" rules cannot bypass our intercept.
	// Common prefixes:
	//   ipsec* - IKEv2/IPsec VPNs (Windscribe, macOS built-in)
	//   utun*  - TUN interfaces (WireGuard, Tailscale, OpenVPN, etc.)
	//   ppp*   - PPTP/L2TP VPNs
	//   tap*   - TAP interfaces (OpenVPN in bridge mode)
	//   tun*   - Legacy TUN interfaces
	// lo0 is excluded since our rules already handle loopback.
	pfVPNInterfacePrefixes = "ipsec,utun,ppp,tap,tun"
)

const (
	// pfProbeDomain is the suffix used for pf interception probe queries.
	// The full probe domain is "_pf-probe-<hex>.<pfProbeDomain>".
	// These queries are sent by a subprocess WITHOUT the _ctrld group GID,
	// so pf should intercept them and redirect to ctrld. If ctrld receives
	// the query, pf interception is working. If not (timeout), rdr is broken.
	// No trailing dot — canonicalName() in the DNS handler strips trailing dots.
	pfProbeDomain = "pf-probe.ctrld.test"

	// pfProbeTimeout is how long to wait for a probe query to arrive at ctrld.
	pfProbeTimeout = 1 * time.Second

	// pfGroupName is the macOS system group used to scope pf exemption rules.
	// Only processes running with this effective GID can bypass the DNS redirect,
	// preventing other applications from circumventing ctrld by querying exempted IPs directly.
	pfGroupName = "_ctrld"

	// pfAnchorName is the pf anchor name used by ctrld for DNS interception.
	// Using reverse-DNS convention to avoid conflicts with other software.
	pfAnchorName = "com.controld.ctrld"

	// pfAnchorDir is the directory where pf anchor files are stored on macOS.
	pfAnchorDir = "/etc/pf.anchors"

	// pfAnchorFile is the full path to ctrld's pf anchor configuration file.
	pfAnchorFile = "/etc/pf.anchors/com.controld.ctrld"
)

// pfState holds the state of the pf DNS interception on macOS.
type pfState struct {
	anchorFile string
	anchorName string
}

// ensureCtrldGroup creates the _ctrld system group if it doesn't exist and returns its GID.
// Uses dscl (macOS Directory Services) to manage the group. This function is idempotent —
// safe to call multiple times across restarts. The group is intentionally never removed
// on shutdown to avoid race conditions during rapid restart cycles.
func ensureCtrldGroup() (int, error) {
	// Check if the group already exists.
	out, err := exec.Command("dscl", ".", "-read", "/Groups/"+pfGroupName, "PrimaryGroupID").CombinedOutput()
	if err == nil {
		// Group exists — parse and return its GID.
		// Output format: "PrimaryGroupID: 350"
		line := strings.TrimSpace(string(out))
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			gid, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0, fmt.Errorf("failed to parse existing group GID from %q: %w", line, err)
			}
			mainLog.Load().Debug().Msgf("DNS intercept: group %s already exists with GID %d", pfGroupName, gid)
			return gid, nil
		}
		return 0, fmt.Errorf("unexpected dscl output for existing group: %q", line)
	}

	// Group doesn't exist — find an unused GID in the 350-450 range (system group range on macOS,
	// above Apple's reserved range but below typical user groups).
	listOut, err := exec.Command("dscl", ".", "-list", "/Groups", "PrimaryGroupID").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to list existing groups: %w (output: %s)", err, strings.TrimSpace(string(listOut)))
	}

	usedGIDs := make(map[int]bool)
	for _, line := range strings.Split(string(listOut), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if gid, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				usedGIDs[gid] = true
			}
		}
	}

	chosenGID := 0
	for gid := 350; gid <= 450; gid++ {
		if !usedGIDs[gid] {
			chosenGID = gid
			break
		}
	}
	if chosenGID == 0 {
		return 0, fmt.Errorf("no unused GID found in range 350-450")
	}

	// Create the group record. Handle eDSRecordAlreadyExists gracefully in case of a
	// race with another ctrld instance.
	createOut, err := exec.Command("dscl", ".", "-create", "/Groups/"+pfGroupName).CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(createOut))
		if !strings.Contains(outStr, "eDSRecordAlreadyExists") {
			return 0, fmt.Errorf("failed to create group record: %w (output: %s)", err, outStr)
		}
	}

	// Set the GID. This is idempotent — dscl overwrites the attribute if it already exists.
	if out, err := exec.Command("dscl", ".", "-create", "/Groups/"+pfGroupName, "PrimaryGroupID", strconv.Itoa(chosenGID)).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("failed to set group GID: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("dscl", ".", "-create", "/Groups/"+pfGroupName, "RealName", "ctrld DNS Intercept Group").CombinedOutput(); err != nil {
		return 0, fmt.Errorf("failed to set group RealName: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	mainLog.Load().Info().Msgf("DNS intercept: created system group %s with GID %d", pfGroupName, chosenGID)
	return chosenGID, nil
}

// setCtrldGroupID sets the process's effective GID to the _ctrld group.
// This must be called before any outbound DNS sockets are created so that
// pf's "group _ctrld" matching applies to ctrld's own DNS queries.
// Only ctrld (running as root with this effective GID) will match the exemption rules,
// preventing other processes from bypassing the DNS redirect.
func setCtrldGroupID(gid int) error {
	if err := syscall.Setegid(gid); err != nil {
		return fmt.Errorf("syscall.Setegid(%d) failed: %w", gid, err)
	}
	mainLog.Load().Info().Msgf("DNS intercept: set process effective GID to %d (%s)", gid, pfGroupName)
	return nil
}

// startDNSIntercept activates pf-based DNS interception on macOS.
// It creates a pf anchor that redirects all outbound DNS (port 53) traffic
// to ctrld's local listener at 127.0.0.1:53. This eliminates the race condition
// with VPN software that overwrites interface DNS settings.
//
// The approach:
//  1. Write a pf anchor file with redirect rules for all non-loopback interfaces
//  2. Load the anchor into pf
//  3. Ensure pf is enabled
//
// ctrld's own upstream queries use DoH (port 443), so they are NOT affected
// by the port 53 redirect. If an "os" upstream is configured (which uses port 53),
// we skip the redirect for traffic from the ctrld process itself.
func (p *prog) startDNSIntercept() error {
	mainLog.Load().Info().Msg("DNS intercept: initializing macOS packet filter (pf) redirect")

	if err := p.validateDNSIntercept(); err != nil {
		return err
	}
	p.pfStabilizing.Store(false)
	p.pfLastRestoreTime.Store(0)
	p.pfBackoffMultiplier.Store(0)
	p.pfExecBackoffUntil.Store(0)
	p.pfIgnoredChangeLastReconcile.Store(0)

	// Set up _ctrld group for pf exemption scoping. This ensures that only ctrld's
	// own DNS queries (matching "group _ctrld" in pf rules) can bypass the redirect.
	// Must happen BEFORE loading pf rules so the effective GID is set when sockets are created.
	gid, err := ensureCtrldGroup()
	if err != nil {
		return fmt.Errorf("dns intercept: failed to create %s group: %w", pfGroupName, err)
	}
	if err := setCtrldGroupID(gid); err != nil {
		return fmt.Errorf("dns intercept: failed to set process GID to %s: %w", pfGroupName, err)
	}

	// Clean up any stale state from a previous crash.
	if _, err := os.Stat(pfAnchorFile); err == nil {
		mainLog.Load().Warn().Msg("DNS intercept: found stale pf anchor file from previous run — cleaning up")
		exec.Command("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput()
		os.Remove(pfAnchorFile)
	}

	// Pre-discover VPN DNS configurations before building initial rules.
	// Without this, there's a startup gap where the initial anchor has no VPN DNS
	// exemptions, causing queries to be intercepted and routed to ctrld. The
	// vpnDNSManager.Refresh() call later would add the exemptions, but stale pf
	// state entries from the gap persist and keep routing packets to lo0.
	// By discovering upfront, the initial rules exclude VPN DNS interfaces from interception.
	var initialExemptions []vpnDNSExemption
	if !hardIntercept {
		initialConfigs := ctrld.DiscoverVPNDNS(context.Background())
		type key struct{ server, iface string }
		seen := make(map[key]bool)
		for _, config := range initialConfigs {
			for _, server := range config.Servers {
				k := key{server, config.InterfaceName}
				if !seen[k] {
					seen[k] = true
					initialExemptions = append(initialExemptions, vpnDNSExemption{
						Server:    server,
						Interface: config.InterfaceName,
					})
				}
			}
		}
		if len(initialExemptions) > 0 {
			mainLog.Load().Info().Msgf("DNS intercept: pre-discovered %d VPN DNS exemptions for initial rules", len(initialExemptions))
		}
	}

	rules := p.buildPFAnchorRules(initialExemptions)

	if err := os.MkdirAll(pfAnchorDir, 0755); err != nil {
		return fmt.Errorf("dns intercept: failed to create pf anchor directory %s: %w", pfAnchorDir, err)
	}
	if err := os.WriteFile(pfAnchorFile, []byte(rules), 0644); err != nil {
		return fmt.Errorf("dns intercept: failed to write pf anchor file %s: %w", pfAnchorFile, err)
	}
	mainLog.Load().Debug().Msgf("DNS intercept: wrote pf anchor file: %s", pfAnchorFile)

	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput()
	if err != nil {
		p.rollbackDNSInterceptStart()
		return fmt.Errorf("dns intercept: failed to load pf anchor: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	mainLog.Load().Debug().Msgf("DNS intercept: loaded pf anchor %q from %s", pfAnchorName, pfAnchorFile)

	if err := p.ensurePFAnchorReference(); err != nil {
		p.rollbackDNSInterceptStart()
		return fmt.Errorf("dns intercept: failed to activate pf anchor references: %w", err)
	}

	out, err = exec.Command("pfctl", "-e").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "already enabled") {
			p.rollbackDNSInterceptStart()
			return fmt.Errorf("dns intercept: failed to enable pf: %w (output: %s)", err, outStr)
		}
	}

	out, err = exec.Command("pfctl", "-a", pfAnchorName, "-sr").CombinedOutput()
	if err != nil {
		mainLog.Load().Warn().Msgf("DNS intercept: could not verify anchor rules: %v", err)
	} else {
		ruleCount := strings.Count(strings.TrimSpace(string(out)), "\n") + 1
		mainLog.Load().Info().Msgf("DNS intercept: pf anchor %q active with %d rules", pfAnchorName, ruleCount)
		mainLog.Load().Debug().Msgf("DNS intercept: active pf rules:\n%s", strings.TrimSpace(string(out)))
	}

	out, err = exec.Command("pfctl", "-a", pfAnchorName, "-sn").CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		mainLog.Load().Debug().Msgf("DNS intercept: active pf NAT/redirect rules:\n%s", strings.TrimSpace(string(out)))
	}

	// Post-load verification: do not publish intercept mode unless PF is
	// authoritatively active; the caller can then use interface-DNS fallback.
	if !p.verifyPFState() {
		p.rollbackDNSInterceptStart()
		return fmt.Errorf("dns intercept: post-load PF verification failed")
	}

	p.dnsInterceptState = &pfState{
		anchorFile: pfAnchorFile,
		anchorName: pfAnchorName,
	}

	// Store the initial set of tunnel interfaces so we can detect changes later.
	p.mu.Lock()
	p.lastTunnelIfaces = discoverTunnelInterfacesForReconcile()
	p.pendingTunnelIfaces = nil
	p.hasPendingTunnelIfaces = false
	p.mu.Unlock()

	lc := p.cfg.FirstListener()
	if lc != nil {
		mainLog.Load().Info().Msgf("DNS intercept: pf redirect active — all outbound DNS (port 53) redirected to %s:%d via anchor %q", lc.IP, lc.Port, pfAnchorName)
	} else {
		mainLog.Load().Info().Msgf("DNS intercept: pf redirect active — all outbound DNS (port 53) redirected via anchor %q", pfAnchorName)
	}

	// Start the pf watchdog to detect and restore rules if another program
	// (e.g., Windscribe desktop, macOS configd) replaces the pf ruleset.
	go p.pfWatchdog()

	return nil
}

func (p *prog) rollbackDNSInterceptStart() {
	if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("DNS intercept: startup rollback could not flush anchor (output: %s)", strings.TrimSpace(string(out)))
	}
	if err := os.Remove(pfAnchorFile); err != nil && !os.IsNotExist(err) {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: startup rollback could not remove anchor file")
	}
	if err := p.removePFAnchorReference(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: startup rollback could not remove anchor references")
	}
}

// ensurePFAnchorReference ensures the running pf ruleset includes our anchor
// declarations. We dump the RUNNING ruleset via "pfctl -sr" (filter+scrub rules)
// and "pfctl -sn" (NAT/rdr rules), check if our references exist, and if not,
// inject them and reload the combined ruleset via stdin.
//
// pf enforces strict rule ordering:
//
//	options → normalization (scrub) → queueing → translation (nat/rdr) → filtering (pass/block/anchor)
//
// "pfctl -sr" returns BOTH scrub-anchor (normalization) AND anchor/pass/block (filter) rules.
// "pfctl -sn" returns rdr-anchor (translation) rules.
// Both commands emit "No ALTQ support in kernel" warnings on stderr.
//
// We must reassemble in correct order: scrub → nat/rdr → filter.
//
// The anchor reference does not survive a reboot, but ctrld re-adds it on every start.
func (p *prog) ensurePFAnchorReference() error {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	// Dump running rules. Use CombinedOutput but filter out stderr warnings.
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to dump running NAT rules: %w (output: %s)", err, strings.TrimSpace(string(natOut)))
	}

	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to dump running filter rules: %w (output: %s)", err, strings.TrimSpace(string(filterOut)))
	}

	// Filter pfctl output into actual pf rules, stripping stderr warnings.
	natLines := pfFilterRuleLines(string(natOut))
	filterLines := pfFilterRuleLines(string(filterOut))

	hasRdrAnchor := pfContainsRule(natLines, rdrAnchorRef)
	hasAnchor := pfContainsRule(filterLines, anchorRef)

	if hasRdrAnchor && hasAnchor {
		// Verify anchor ordering: our anchor should appear before other anchors
		// for reliable DNS interception priority. Log a warning if out of order,
		// but don't force a reload (the interface-specific rules in our anchor
		// provide a secondary safety net even if ordering is suboptimal).
		p.checkAnchorOrdering(filterLines, anchorRef)
		mainLog.Load().Debug().Msg("DNS intercept: anchor references already present in running ruleset")
		return nil
	}

	mainLog.Load().Info().Msg("DNS intercept: injecting anchor references into running pf ruleset")

	// Separate scrub rules from filter rules (pfctl -sr returns both).
	// scrub/scrub-anchor = normalization, must come BEFORE translation.
	var scrubLines, pureFilterLines []string
	for _, line := range filterLines {
		if strings.HasPrefix(line, "scrub") {
			scrubLines = append(scrubLines, line)
		} else {
			pureFilterLines = append(pureFilterLines, line)
		}
	}

	// Inject our references if missing. PREPEND both references to ensure our
	// anchor is evaluated BEFORE any other anchors (e.g., Windscribe's
	// "vpn_app_traffic"). pf evaluates rules top-to-bottom, so "quick"
	// rules in whichever anchor appears first win. By prepending, our DNS
	// intercept rules match port 53 traffic before a VPN app's broader
	// "pass out quick on <iface> all" rules in their anchor.
	if !hasRdrAnchor {
		natLines = append([]string{rdrAnchorRef}, natLines...)
	}
	if !hasAnchor {
		pureFilterLines = append([]string{anchorRef}, pureFilterLines...)
	}

	// Reassemble in pf's required order: scrub → translation → filtering.
	//
	// KNOWN GAP: no options section is emitted, so this reload drops the running pf
	// options - timeouts, limits and any third-party "set skip" directives - which by
	// pf semantics revert to defaults.
	//
	// They cannot simply be carried across, because Apple's pfctl offers no way to read
	// them: pfctl(8) accepts -s nat, queue, rules, Anchors, states, Sources, info,
	// References, labels, timeouts, memory, Tables, osfp, Interfaces and all, with no
	// options modifier. A fix therefore likely means not rebuilding the main ruleset
	// from scratch at all. What macOS pf does to system options on a reload like this
	// needs confirming on a host - tracked as follow-up to #573.
	var combined strings.Builder
	for _, line := range scrubLines {
		combined.WriteString(line + "\n")
	}
	for _, line := range natLines {
		combined.WriteString(line + "\n")
	}
	for _, line := range pureFilterLines {
		combined.WriteString(line + "\n")
	}

	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(combined.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load pf ruleset with anchor references: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	mainLog.Load().Info().Msg("DNS intercept: anchor references active in running pf ruleset")
	return nil
}

// checkAnchorOrdering logs a warning if our anchor reference is not the first
// anchor in the filter ruleset. When another anchor (e.g., Windscribe's
// "vpn_app_traffic") appears before ours, its "quick" rules may match
// DNS traffic first. The interface-specific tunnel rules in our anchor provide
// a secondary defense, but first position is still preferred.
func (p *prog) checkAnchorOrdering(filterLines []string, ourAnchorRef string) {
	for _, line := range filterLines {
		if strings.HasPrefix(line, "anchor ") {
			if strings.Contains(line, ourAnchorRef) {
				// Our anchor is first — ideal ordering.
				return
			}
			// Another anchor appears before ours.
			mainLog.Load().Warn().Msgf("DNS intercept: anchor ordering suboptimal — %q appears before our anchor %q. "+
				"Interface-specific rules provide fallback protection, but prepending is preferred.", line, pfAnchorName)
			return
		}
	}
}

// stopDNSIntercept removes all pf rules and cleans up the DNS interception.
func (p *prog) stopDNSIntercept() error {
	state, ok := p.dnsInterceptState.(*pfState)
	if !ok || state == nil {
		mainLog.Load().Debug().Msg("DNS intercept: no pf state to clean up")
		return nil
	}

	// Revoke lifecycle state and cancel future owners before waiting for any
	// in-flight PF mutation. A mutation that already owns the lane may finish,
	// but final cleanup always runs after it and no new owner can start.
	p.dnsInterceptState = nil
	pfShutdownStateRevokedForTest()
	p.mu.Lock()
	if p.pfStabilizeCancel != nil {
		p.pfStabilizeCancel()
		p.pfStabilizeCancel = nil
	}
	p.lastTunnelIfaces = nil
	p.pendingTunnelIfaces = nil
	p.hasPendingTunnelIfaces = false
	p.mu.Unlock()
	p.pfStabilizing.Store(false)

	p.pfDelayedRecheckMu.Lock()
	for _, timer := range p.pfDelayedRecheckTimers {
		if timer != nil {
			timer.Stop()
		}
	}
	p.pfDelayedRecheckTimers = nil
	p.pfDelayedRecheckMu.Unlock()

	for !p.pfEnsureRunning.CompareAndSwap(false, true) {
		time.Sleep(10 * time.Millisecond)
	}
	defer p.pfEnsureRunning.Store(false)

	mainLog.Load().Info().Msg("DNS intercept: shutting down pf redirect")
	out, err := exec.Command("pfctl", "-a", state.anchorName, "-F", "all").CombinedOutput()
	if err != nil {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to flush pf anchor %q: %v (output: %s)",
			state.anchorName, err, strings.TrimSpace(string(out)))
	} else {
		mainLog.Load().Debug().Msgf("DNS intercept: flushed pf anchor %q", state.anchorName)
	}

	if err := os.Remove(state.anchorFile); err != nil && !os.IsNotExist(err) {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to remove anchor file %s: %v", state.anchorFile, err)
	} else {
		mainLog.Load().Debug().Msgf("DNS intercept: removed anchor file %s", state.anchorFile)
	}

	if err := p.removePFAnchorReference(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to remove anchor references from running pf ruleset")
	}

	p.pfLastRestoreTime.Store(0)
	p.pfBackoffMultiplier.Store(0)
	p.pfExecBackoffUntil.Store(0)
	p.pfIgnoredChangeLastReconcile.Store(0)
	mainLog.Load().Info().Msg("DNS intercept: pf shutdown complete")
	return nil
}

// removePFAnchorReference removes our anchor references from the running pf ruleset.
// Uses the same dump → filter → reassemble approach as ensurePFAnchorReference.
// The anchor itself is already flushed by stopDNSIntercept, so even if removal
// fails, the empty anchor is a no-op.
func (p *prog) removePFAnchorReference() error {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to dump running NAT rules: %w (output: %s)", err, strings.TrimSpace(string(natOut)))
	}
	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to dump running filter rules: %w (output: %s)", err, strings.TrimSpace(string(filterOut)))
	}

	// Nothing of ours in the running ruleset means nothing to remove - and the reload
	// below would reset system-wide pf options on the way past. Startup rollback reaches
	// here after failures that happen before the references are ever added.
	if !pfAnchorReferencesPresent(string(natOut), string(filterOut), pfAnchorName) {
		mainLog.Load().Debug().Msg("DNS intercept: no anchor references in the running pf ruleset — nothing to remove")
		return nil
	}

	// Filter and remove our lines.
	natLines := pfFilterRuleLines(string(natOut))
	filterLines := pfFilterRuleLines(string(filterOut))

	var cleanNat []string
	for _, line := range natLines {
		if !strings.Contains(line, rdrAnchorRef) {
			cleanNat = append(cleanNat, line)
		}
	}

	// Separate scrub from filter, remove our anchor ref.
	var scrubLines, cleanFilter []string
	for _, line := range filterLines {
		if strings.Contains(line, anchorRef) {
			continue
		}
		if strings.HasPrefix(line, "scrub") {
			scrubLines = append(scrubLines, line)
		} else {
			cleanFilter = append(cleanFilter, line)
		}
	}

	// Reassemble in correct order: scrub → translation → filtering.
	var combined strings.Builder
	for _, line := range scrubLines {
		combined.WriteString(line + "\n")
	}
	for _, line := range cleanNat {
		combined.WriteString(line + "\n")
	}
	for _, line := range cleanFilter {
		combined.WriteString(line + "\n")
	}

	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(combined.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload pf ruleset without anchor references: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	mainLog.Load().Debug().Msg("DNS intercept: removed anchor references from running pf ruleset")
	return nil
}

// pfAddressFamily returns "inet" for IPv4 addresses and "inet6" for IPv6 addresses.
// Used to generate pf rules with the correct address family for each IP.
// flushPFStates flushes ALL pf state entries. Called after anchor reloads to ensure
// packets are re-evaluated against the new rules instead of matching stale state
// entries from the old ruleset. This is necessary because pf checks its state table
// BEFORE rule evaluation — a state entry created by a route-to rule will keep
// routing packets to lo0 even after VPN DNS interfaces are excluded from interception.
//
// We flush all states (not just port 53) because:
//  1. pfctl doesn't support port-based state killing
//  2. State flush is fast and brief — existing TCP connections (DoH) will
//     re-establish quickly, and UDP connections are stateless at the transport level
func flushPFStates() {
	if out, err := exec.Command("pfctl", "-F", "states").CombinedOutput(); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("DNS intercept: failed to flush pf states (output: %s)", strings.TrimSpace(string(out)))
	} else {
		mainLog.Load().Debug().Msg("DNS intercept: flushed pf states after anchor reload")
	}
}

func pfAddressFamily(ip string) string {
	if addr := net.ParseIP(ip); addr != nil && addr.To4() == nil {
		return "inet6"
	}
	return "inet"
}

// discoverTunnelInterfaces returns the names of active VPN/tunnel network interfaces.
// These interfaces may have pf rules from VPN software (e.g., Windscribe's "pass out quick
// on ipsec0") that would match DNS traffic before our anchor rules. By discovering them,
// we can add interface-specific intercept rules that take priority.
func discoverTunnelInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to enumerate network interfaces")
		return nil
	}

	prefixes := strings.Split(pfVPNInterfacePrefixes, ",")
	var tunnels []string

	for _, iface := range ifaces {
		// Only consider interfaces that are up — down interfaces can't carry DNS traffic.
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(iface.Name, strings.TrimSpace(prefix)) {
				tunnels = append(tunnels, iface.Name)
				break
			}
		}
	}

	if len(tunnels) > 0 {
		mainLog.Load().Debug().Msgf("DNS intercept: discovered active tunnel interfaces: %v", tunnels)
	}
	return tunnels
}

var discoverTunnelInterfacesForReconcile = discoverTunnelInterfaces

// dnsInterceptSupported reports whether DNS intercept mode is supported on this platform.
func dnsInterceptSupported() bool {
	_, err := exec.LookPath("pfctl")
	return err == nil
}

// validateDNSIntercept checks that the system meets requirements for DNS intercept mode.
func (p *prog) validateDNSIntercept() error {
	if !dnsInterceptSupported() {
		return fmt.Errorf("dns intercept: pfctl not found — pf is required for DNS intercept on macOS")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("dns intercept: root privileges required for pf filter management")
	}

	if err := os.MkdirAll(filepath.Dir(pfAnchorFile), 0755); err != nil {
		return fmt.Errorf("dns intercept: cannot create anchor directory: %w", err)
	}

	if p.cfg != nil {
		for name, uc := range p.cfg.Upstream {
			if uc.Type == "os" || uc.Type == "" {
				return fmt.Errorf("dns intercept: upstream %q uses OS resolver (port 53) which would create "+
					"a redirect loop with pf. Use DoH upstreams (--proto doh) with dns-intercept mode", name)
			}
		}
	}

	return nil
}

// buildPFAnchorRules generates the pf anchor rules for DNS interception.
// vpnExemptions are VPN DNS server+interface pairs to exempt from interception.
//
// macOS pf "rdr" rules only apply to forwarded traffic, NOT locally-originated
// packets. To intercept DNS from the machine itself, we use a two-step approach:
//  1. "pass out route-to lo0" forces outbound DNS through the loopback interface
//  2. "rdr on lo0" catches it on loopback and redirects to our listener
//
// STATE AND ROUTING (critical for VPN firewall coexistence):
//   - route-to rules: keep state (default). State is floating (matches on any interface),
//     but "pass out on lo0 no state" ensures no state exists on the lo0 outbound path,
//     so rdr still fires on the lo0 inbound pass.
//   - pass out on lo0: NO STATE — prevents state from being created on lo0 outbound,
//     which would match inbound and bypass rdr.
//   - rdr: no "pass" keyword — packet goes through filter so "pass in" creates state.
//   - pass in on lo0: keep state + REPLY-TO lo0 — creates state for response routing
//     AND forces the response back through lo0. Without reply-to, the response to a
//     VPN client IP gets routed through the VPN tunnel and is lost.
//
// ctrld's own OS resolver nameservers (used for bootstrap DNS) must be exempted
// from the redirect to prevent ctrld from querying itself in a loop.
//
// pf requires strict rule ordering: translation (rdr) BEFORE filtering (pass).
func (p *prog) buildPFAnchorRules(vpnExemptions []vpnDNSExemption) string {
	return p.buildPFAnchorRulesForTunnels(vpnExemptions, discoverTunnelInterfacesForReconcile())
}

func (p *prog) buildPFAnchorRulesForTunnels(vpnExemptions []vpnDNSExemption, tunnelIfaces []string) string {
	// Read the actual listener address from config. In intercept mode, ctrld may
	// be on a non-standard port (e.g., 127.0.0.1:5354) if mDNSResponder holds *:53.
	// The pf rdr rules must redirect to wherever ctrld is actually listening.
	listenerIP := "127.0.0.1"
	listenerPort := 53
	if lc := p.cfg.FirstListener(); lc != nil {
		if lc.IP != "" && lc.IP != "0.0.0.0" && lc.IP != "::" {
			listenerIP = lc.IP
		} else if lc.IP == "0.0.0.0" || lc.IP == "::" {
			mainLog.Load().Warn().Str("configured_ip", lc.IP).
				Msg("DNS intercept: listener configured with wildcard IP, using 127.0.0.1 for pf rules")
		}
		if lc.Port != 0 {
			listenerPort = lc.Port
		}
	}
	listenerAddr := fmt.Sprintf("%s port %d", listenerIP, listenerPort)

	var rules strings.Builder
	rules.WriteString("# ctrld DNS Intercept Mode\n")
	rules.WriteString("# Intercepts locally-originated DNS (port 53) via route-to + rdr on lo0.\n")
	rules.WriteString("#\n")
	rules.WriteString("# How it works:\n")
	rules.WriteString("#   1. \"pass out route-to lo0\" forces outbound DNS through the loopback interface\n")
	rules.WriteString(fmt.Sprintf("#   2. \"rdr on lo0\" catches it on loopback and redirects to ctrld at %s\n", listenerAddr))
	rules.WriteString("#\n")
	rules.WriteString("# All ctrld traffic is blanket-exempted via \"pass out quick group " + pfGroupName + "\",\n")
	rules.WriteString("# ensuring ctrld's DoH/DoT upstream connections and DNS queries are never\n")
	rules.WriteString("# blocked by VPN firewalls (e.g., Windscribe's \"block drop all\").\n")
	rules.WriteString("#\n")
	rules.WriteString("# pf requires strict rule ordering: translation (rdr) BEFORE filtering (pass).\n\n")

	// --- Translation rules (must come first per pf ordering) ---
	// Uses "rdr" without "pass" so the redirected packet continues to filter evaluation.
	// The filter rule "pass in on lo0 ... to 127.0.0.1 port 53 keep state" then creates
	// a stateful entry that handles response routing. Using "rdr pass" would skip filter
	// evaluation, and its implicit state alone is insufficient for response delivery —
	// proven by commit 51cf029 where responses were silently dropped.
	rules.WriteString("# --- Translation rules (rdr) ---\n")

	rules.WriteString("# Redirect DNS on loopback to ctrld's listener.\n")
	rules.WriteString(fmt.Sprintf("rdr on lo0 inet proto udp from any to ! %s port 53 -> %s\n", listenerIP, listenerAddr))
	rules.WriteString(fmt.Sprintf("rdr on lo0 inet proto tcp from any to ! %s port 53 -> %s\n", listenerIP, listenerAddr))
	// No IPv6 rdr — IPv6 DNS is blocked at the filter level (see below).
	rules.WriteString("\n")

	// --- Filtering rules ---
	rules.WriteString("# --- Filtering rules (pass) ---\n\n")

	// Blanket exemption: allow ALL outbound traffic from ctrld (group _ctrld) through
	// without any pf filtering or redirection. This is critical for VPN coexistence —
	// VPN apps like Windscribe load "block drop all" rulesets that would otherwise block
	// ctrld's DoH connections (TCP 443) to upstream DNS servers (e.g., 76.76.2.22).
	// Because our anchor is prepended before other anchors, this rule evaluates first,
	// ensuring ctrld's traffic is never blocked by downstream firewall rules.
	//
	// The per-IP exemptions below (OS resolver, VPN DNS) remain as defense-in-depth:
	// they prevent DNS redirect loops for ctrld's own port-53 queries specifically,
	// while this rule handles everything else (DoH, DoT, health checks, etc.).
	rules.WriteString("# Blanket exemption: let all ctrld traffic through regardless of other pf rules.\n")
	rules.WriteString("# VPN firewalls (e.g., Windscribe's \"block drop all\") would otherwise block\n")
	rules.WriteString("# ctrld's DoH (TCP 443) connections to upstream DNS servers.\n")
	rules.WriteString(fmt.Sprintf("pass out quick group %s\n\n", pfGroupName))

	// Exempt OS resolver nameservers (read live from the global OS resolver)
	// so ctrld's bootstrap DNS queries don't get redirected back to itself.
	// IPv4 addresses use "inet", IPv6 addresses use "inet6".
	osNS := ctrld.OsResolverNameservers()
	if len(osNS) > 0 {
		rules.WriteString("# Exempt OS resolver nameservers (ctrld bootstrap DNS) from redirect.\n")
		rules.WriteString("# Scoped to group " + pfGroupName + " so only ctrld's own queries are exempted,\n")
		rules.WriteString("# preventing other processes from bypassing the redirect by querying these IPs.\n")
		for _, ns := range osNS {
			host, _, _ := net.SplitHostPort(ns)
			if host == "" {
				host = ns
			}
			af := pfAddressFamily(host)
			rules.WriteString(fmt.Sprintf("pass out quick on ! lo0 %s proto { udp, tcp } from any to %s port 53 group %s\n", af, host, pfGroupName))
		}
		rules.WriteString("\n")
	}

	// Build sets of VPN DNS interfaces and server IPs for exclusion from intercept rules.
	//
	// VPN DNS handlers that use macOS Network Extensions (Tailscale MagicDNS, modern
	// Cisco AnyConnect, F5 BIG-IP) intercept packets at the NE layer — BEFORE pf sees
	// them on the return path, but AFTER pf's outbound rules fire. Any pf rule that
	// touches packets on a VPN DNS interface (even "pass" with "keep state") interferes
	// with the NE's packet handling, causing timeouts.
	//
	// Solution: exclude VPN DNS interfaces from tunnel intercept rules entirely, and
	// exclude VPN DNS server IPs from the generic intercept rule. This lets all DNS
	// traffic to/from VPN DNS flow naturally without any pf interference.
	//
	// EXIT MODE EXCEPTION: When a VPN is in exit/full-tunnel mode (VPN DNS server is
	// also the system default resolver), we do NOT exempt the interface. In exit mode,
	// all traffic routes through the VPN, so exempting the interface would bypass ctrld
	// for ALL DNS — losing profile enforcement (blocking, filtering). Instead, we keep
	// intercepting and let ctrld's VPN DNS split routing + group exemption handle it.
	vpnDNSIfaces := make(map[string]bool)           // non-exit interfaces to skip in tunnel intercept
	vpnDNSIfacePassthrough := make(map[string]bool) // non-exit interfaces needing passthrough rules
	vpnDNSServerIPs := make(map[string]bool)        // IPs to exclude from generic intercept
	for _, ex := range vpnExemptions {
		if ex.Interface != "" && !ex.IsExitMode {
			vpnDNSIfaces[ex.Interface] = true
			vpnDNSIfacePassthrough[ex.Interface] = true
		}
		vpnDNSServerIPs[ex.Server] = true
	}

	// Group-scoped exemptions for ctrld's own VPN DNS queries.
	// When ctrld's proxy() VPN DNS split routing sends queries to VPN DNS servers,
	// these rules let ctrld's traffic through without being intercepted by the
	// generic route-to rule. Scoped to group _ctrld so only ctrld benefits.
	if len(vpnExemptions) > 0 {
		rules.WriteString("# Exempt VPN DNS servers: ctrld's own queries (group-scoped).\n")
		seen := make(map[string]bool)
		for _, ex := range vpnExemptions {
			if !seen[ex.Server] {
				seen[ex.Server] = true
				af := pfAddressFamily(ex.Server)
				rules.WriteString(fmt.Sprintf("pass out quick on ! lo0 %s proto { udp, tcp } from any to %s port 53 group %s\n", af, ex.Server, pfGroupName))
			}
		}
		rules.WriteString("\n")
	}

	// NOTE: IPv6 DNS is now intercepted (not blocked). ctrld listens on [::1] and pf
	// redirects IPv6 DNS the same way as IPv4. This eliminates the ~1s timeout caused by
	// blocking IPv6 DNS (BSD doesn't deliver ICMP errors to unconnected UDP sockets).

	// --- VPN DNS interface passthrough (split DNS mode only) ---
	//
	// In split DNS mode, the VPN's DNS handler (e.g., Tailscale MagicDNS) runs as a
	// Network Extension that intercepts packets on its tunnel interface. MagicDNS then
	// forwards queries to its own upstream nameservers (e.g., 10.0.0.11) — IPs we
	// can't know in advance. Without these rules, pf's generic "on !lo0" intercept
	// catches MagicDNS's upstream queries, routing them back to ctrld in a loop.
	//
	// These "pass" rules (no route-to) let MagicDNS's upstream queries pass through.
	// Traffic TO the VPN DNS server itself (e.g., 100.100.100.100) is excluded so those
	// queries get intercepted → ctrld enforces its profile on non-search-domain queries.
	//
	// NOT applied in exit mode — in exit mode, all traffic routes through the VPN
	// interface, so exempting it would bypass ctrld's profile enforcement entirely.
	if len(vpnDNSIfacePassthrough) > 0 {
		// Build table of VPN DNS server IPs to exclude from passthrough.
		// Queries TO these IPs must still be intercepted (profile enforcement).
		// Only MagicDNS's upstream queries to other IPs should pass through.
		var vpnDNSTableMembers []string
		for ip := range vpnDNSServerIPs {
			if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil {
				vpnDNSTableMembers = append(vpnDNSTableMembers, ip)
			}
		}
		if len(vpnDNSTableMembers) > 0 {
			rules.WriteString("# Table of VPN DNS server IPs — queries to these must be intercepted.\n")
			rules.WriteString(fmt.Sprintf("table <vpn_dns> { %s }\n", strings.Join(vpnDNSTableMembers, ", ")))
		}
		rules.WriteString("# --- VPN DNS interface passthrough (split DNS mode) ---\n")
		rules.WriteString("# Pass MagicDNS upstream queries; intercept queries TO MagicDNS itself.\n")
		for iface := range vpnDNSIfacePassthrough {
			if len(vpnDNSTableMembers) > 0 {
				rules.WriteString(fmt.Sprintf("pass out quick on %s inet proto udp from any to ! <vpn_dns> port 53\n", iface))
				rules.WriteString(fmt.Sprintf("pass out quick on %s inet proto tcp from any to ! <vpn_dns> port 53\n", iface))
			} else {
				rules.WriteString(fmt.Sprintf("pass out quick on %s inet proto udp from any to any port 53\n", iface))
				rules.WriteString(fmt.Sprintf("pass out quick on %s inet proto tcp from any to any port 53\n", iface))
			}
		}
		rules.WriteString("\n")
	}

	// --- Interface-specific VPN/tunnel intercept rules ---
	// VPN apps (e.g., Windscribe, Cisco AnyConnect) often add pf rules like:
	//   pass out quick on ipsec0 inet all flags S/SA keep state
	// inside their own anchors. If their anchor is evaluated before ours, their
	// "quick" match on the VPN interface captures DNS traffic before our generic
	// "on ! lo0" rule can intercept it. To counter this, we add explicit intercept
	// rules for each active tunnel interface. These use "quick" and match port 53
	// specifically, so they take priority over the VPN app's broader "all" rules
	// regardless of anchor ordering.
	//
	// NOTE: If anchor ordering alone proves insufficient in the future, a "nuclear
	// option" is available: inject DNS intercept rules directly into the MAIN pf
	// ruleset (not inside our anchor). Main ruleset rules are evaluated before ALL
	// anchors, making them impossible for another app to override without explicitly
	// removing them. See docs/dns-intercept-mode.md for details.
	if len(tunnelIfaces) > 0 {
		rules.WriteString("# --- VPN/tunnel interface intercept rules ---\n")
		rules.WriteString("# Explicit intercept on tunnel interfaces prevents VPN apps from capturing\n")
		rules.WriteString("# DNS traffic with their own broad \"pass out quick on <iface>\" rules.\n")
		rules.WriteString("# These port-53-specific rules take priority over broader \"all\" matches.\n")
		rules.WriteString("#\n")
		rules.WriteString("# Interfaces with VPN DNS servers (from scutil) are EXCLUDED — those carry\n")
		rules.WriteString("# DNS traffic for Network Extension-based VPNs (e.g., Tailscale MagicDNS)\n")
		rules.WriteString("# that must flow without any pf interference.\n")
		for _, iface := range tunnelIfaces {
			if vpnDNSIfaces[iface] {
				rules.WriteString(fmt.Sprintf("# Skipped %s — VPN DNS interface (Network Extension needs unintercepted flow)\n", iface))
				continue
			}
			rules.WriteString(fmt.Sprintf("pass out quick on %s route-to lo0 inet proto udp from any to ! %s port 53\n", iface, listenerIP))
			rules.WriteString(fmt.Sprintf("pass out quick on %s route-to lo0 inet proto tcp from any to ! %s port 53\n", iface, listenerIP))
			// No IPv6 route-to — IPv6 DNS is blocked, not intercepted.
		}
		rules.WriteString("\n")
	}

	// Force all remaining outbound IPv4 DNS through loopback for interception.
	// VPN DNS server IPs are excluded — those must reach their VPN DNS handler
	// without pf interference (especially for Network Extension-based VPNs).
	//
	// IMPORTANT: pf expands negated lists like { !a, !b } into separate rules where
	// each rule matches everything the other excludes — effectively matching ALL addresses.
	// This is a well-documented pf pitfall (OpenBSD FAQ, "negated lists").
	// Fix: use a pf table with a single negated match: "to ! <table>".
	// Force all remaining outbound IPv4 DNS through loopback for interception.
	// Only loopback (127.0.0.1) is excluded — ctrld's own outbound queries to VPN DNS
	// servers are handled by the group-scoped exemption rules above (group _ctrld).
	rules.WriteString("# Force remaining outbound IPv4 DNS through loopback for interception.\n")
	rules.WriteString(fmt.Sprintf("pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! %s port 53\n", listenerIP))
	rules.WriteString(fmt.Sprintf("pass out quick on ! lo0 route-to lo0 inet proto tcp from any to ! %s port 53\n\n", listenerIP))

	// Block all outbound IPv6 DNS. ctrld only intercepts IPv4 DNS via the loopback
	// redirect. IPv6 DNS interception on macOS is not feasible because the kernel rejects
	// sendmsg from [::1] to global unicast IPv6 (EINVAL), and pf's nat-on-lo0 doesn't
	// fire for route-to'd packets. Blocking forces macOS to fall back to IPv4 DNS,
	// which is fully intercepted. See docs/pf-dns-intercept.md for details.
	rules.WriteString("# Block outbound IPv6 DNS — ctrld intercepts IPv4 only.\n")
	rules.WriteString("# macOS falls back to IPv4 DNS automatically.\n")
	rules.WriteString("block out quick on ! lo0 inet6 proto { udp, tcp } from any to any port 53\n\n")

	// Allow route-to'd DNS packets to pass outbound on lo0.
	// Without this, VPN firewalls with "block drop all" (e.g., Windscribe) drop the packet
	// after route-to redirects it to lo0 but before it can reflect inbound for rdr processing.
	//
	// CRITICAL: This rule MUST use "no state". If it created state, that state would match
	// the packet when it reflects inbound on lo0, causing pf to fast-path it and bypass
	// rdr entirely. With "no state", the inbound packet gets fresh evaluation and rdr fires.
	rules.WriteString("# Pass route-to'd DNS outbound on lo0 — no state to avoid bypassing rdr inbound.\n")
	rules.WriteString(fmt.Sprintf("pass out quick on lo0 inet proto udp from any to ! %s port 53 no state\n", listenerIP))
	rules.WriteString(fmt.Sprintf("pass out quick on lo0 inet proto tcp from any to ! %s port 53 no state\n", listenerIP))
	// No IPv6 lo0 pass — IPv6 DNS is blocked, not routed through lo0.
	rules.WriteString("\n")

	// Allow the redirected traffic through on loopback (inbound after rdr).
	//
	// "reply-to lo0" is CRITICAL for VPN coexistence. Without it, ctrld's response to a
	// VPN client IP (e.g., 100.94.163.168) gets routed via the VPN tunnel interface
	// (utun420) by the kernel routing table — the response enters the tunnel and is lost.
	// "reply-to lo0" forces pf to route the response back through lo0 regardless of the
	// kernel routing table, ensuring it stays local and reaches the client process.
	//
	// "keep state" (the default) creates the stateful entry used by reply-to to route
	// the response. The rdr NAT state handles the address rewrite on the response
	// (source 127.0.0.1 → original DNS server IP, e.g., 10.255.255.3).
	rules.WriteString("# Accept redirected DNS — reply-to lo0 forces response through loopback.\n")
	rules.WriteString(fmt.Sprintf("pass in quick on lo0 reply-to lo0 inet proto { udp, tcp } from any to %s\n", listenerAddr))
	// No IPv6 pass-in — IPv6 DNS is blocked, not redirected to [::1].

	return rules.String()
}

// verifyPFState checks that the pf ruleset is correctly configured after loading.
// It verifies both the anchor references in the main ruleset and the rules within
// our anchor. Failures are logged at ERROR level to make them impossible to miss.
func (p *prog) verifyPFState() bool {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)
	verified := true

	// Check main ruleset for anchor references (rdr-anchor in translation rules).
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		p.pfBackoffResourceExhaustion(err, natOut, "verify NAT rules")
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump NAT rules")
		verified = false
	} else {
		natStr := string(natOut)
		if !strings.Contains(natStr, rdrAnchorRef) {
			mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — rdr-anchor reference missing from running NAT rules")
			verified = false
		}
	}

	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		p.pfBackoffResourceExhaustion(err, filterOut, "verify filter rules")
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump filter rules")
		verified = false
	} else if !strings.Contains(string(filterOut), anchorRef) {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor reference missing from running filter rules")
		verified = false
	}

	// Check our anchor has rules loaded.
	anchorFilter, err := exec.Command("pfctl", "-a", pfAnchorName, "-sr").CombinedOutput()
	if err != nil {
		p.pfBackoffResourceExhaustion(err, anchorFilter, "verify anchor filter rules")
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump anchor filter rules")
		verified = false
	} else if pfRulesetEmpty(string(anchorFilter)) {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor has no filter rules loaded")
		verified = false
	}

	anchorNat, err := exec.Command("pfctl", "-a", pfAnchorName, "-sn").CombinedOutput()
	if err != nil {
		p.pfBackoffResourceExhaustion(err, anchorNat, "verify anchor NAT rules")
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump anchor NAT rules")
		verified = false
	} else if pfRulesetEmpty(string(anchorNat)) {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor has no NAT/redirect rules loaded")
		verified = false
	}

	// There is deliberately no "set skip on lo0" check here, even though such a skip
	// would make our rdr rules on loopback dead.
	//
	// macOS offers no way to query it as text: pfctl(8) accepts -s nat, queue, rules,
	// Anchors, states, Sources, info, References, labels, timeouts, memory, Tables,
	// osfp, Interfaces and all - there is no options or skip modifier. Since this
	// verification gates whether intercept mode may publish, a check that cannot
	// succeed here would roll back every start.
	//
	// probePFIntercept() detects the condition functionally instead: it sends a real
	// query from outside the _ctrld group and confirms the listener received the
	// redirect, which cannot succeed if pf is bypassing loopback. An explicit check is
	// follow-up work - pfctl(8) documents "-s Interfaces -v" as listing which
	// interfaces have skip rules activated, but its output shape needs confirming on a
	// host that actually has a skip configured before anything parses it.

	if verified {
		mainLog.Load().Info().Msg("DNS intercept: post-load verification passed — all pf rules confirmed active")
	}
	return verified
}

// resetUpstreamTransports forces all DoH/DoT/DoQ upstreams to re-bootstrap their
// network transports. This is called when the pf watchdog detects that the pf state
// table was flushed (e.g., by Windscribe running "pfctl -f"), which kills all existing
// TCP connections including ctrld's DoH connections to upstream DNS servers.
//
// Without this, Go's http.Transport keeps trying to use dead connections until each
// request hits its 5s context deadline — causing a ~5s DNS blackout.
//
// ForceReBootstrap() immediately creates a new transport (closing old idle
// connections), so new queries use fresh connections without waiting for the
// lazy re-bootstrap flag. This reduces the blackout from ~5s to ~100ms.
func (p *prog) resetUpstreamTransports() {
	if p.cfg == nil {
		return
	}
	count := 0
	for _, uc := range p.cfg.Upstream {
		if uc == nil {
			continue
		}
		uc.ForceReBootstrap()
		count++
	}
	if count > 0 {
		mainLog.Load().Info().Msgf("DNS intercept watchdog: force-reset %d upstream transport(s) — pf state flush likely killed existing DoH connections", count)
	}
}

var (
	ensurePFAnchorReferenceForRestore = func(p *prog) error {
		return p.ensurePFAnchorReference()
	}
	rebuildPFAnchorRulesForReconcile = func(p *prog, exemptions []vpnDNSExemption) ([]string, error) {
		return p.rebuildPFAnchorRules(exemptions)
	}
	restorePFAnchorForReconcile = func(p *prog, reason string) pfAnchorCheckResult {
		return p.restorePFAnchor(reason)
	}
	pfShutdownStateRevokedForTest = func() {}
)

func (p *prog) rebuildPFAnchorRules(vpnExemptions []vpnDNSExemption) ([]string, error) {
	tunnelIfaces := append([]string(nil), discoverTunnelInterfacesForReconcile()...)
	rulesStr := p.buildPFAnchorRulesForTunnels(vpnExemptions, tunnelIfaces)
	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		return nil, fmt.Errorf("write anchor file: %w", err)
	}
	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("load rebuilt anchor: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	flushPFStates()
	return tunnelIfaces, nil
}

func (p *prog) restorePFAnchor(reason string) pfAnchorCheckResult {
	return p.restorePFAnchorWithTransportReset(reason, true)
}

func (p *prog) restorePFAnchorWithTransportReset(reason string, resetTransports bool) pfAnchorCheckResult {
	if p.dnsInterceptState == nil {
		return pfAnchorCheckSkipped
	}
	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	mainLog.Load().Info().Str("reason", reason).Msg("DNS intercept: restoring pf anchor")
	if err := ensurePFAnchorReferenceForRestore(p); err != nil {
		p.pfBackoffResourceExhaustion(err, nil, "restore anchor references")
		if resetTransports {
			p.resetUpstreamTransports()
		}
		mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to restore anchor references")
		return pfAnchorCheckFailed
	}

	tunnelIfaces, err := rebuildPFAnchorRulesForReconcile(p, vpnExemptions)
	if err != nil {
		p.pfBackoffResourceExhaustion(err, nil, "rebuild anchor")
		if resetTransports {
			p.resetUpstreamTransports()
		}
		mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to rebuild anchor")
		return pfAnchorCheckFailed
	}

	// rebuildPFAnchorRules flushed PF states after the successful load. Reset
	// transports even if the authoritative verification below fails, otherwise
	// DoH can remain pinned to connections invalidated by that flush.
	if resetTransports {
		p.resetUpstreamTransports()
	}
	if !p.verifyPFState() {
		mainLog.Load().Error().Str("reason", reason).Msg("DNS intercept: rebuilt anchor failed post-load verification")
		return pfAnchorCheckFailed
	}
	if p.vpnDNS != nil {
		p.vpnDNS.markInterceptExemptionsApplied(vpnExemptions)
	}
	p.commitPFReconcileState(tunnelIfaces)
	p.pfLastRestoreTime.Store(time.Now().UnixMilli())
	mainLog.Load().Info().Str("reason", reason).Msg("DNS intercept: pf anchor restored successfully")
	return pfAnchorCheckRestored
}

func (p *prog) commitPFReconcileState(tunnelIfaces []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastTunnelIfaces = append([]string(nil), tunnelIfaces...)
	if p.hasPendingTunnelIfaces && stringSlicesEqual(p.pendingTunnelIfaces, tunnelIfaces) {
		p.pendingTunnelIfaces = nil
		p.hasPendingTunnelIfaces = false
	}
}

func (p *prog) clearPendingTunnelReconcile() {
	p.mu.Lock()
	p.pendingTunnelIfaces = nil
	p.hasPendingTunnelIfaces = false
	p.mu.Unlock()
}

func (p *prog) hasPendingTunnelReconcile() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hasPendingTunnelIfaces
}

func (p *prog) reconcilePFAnchorForTunnelChange() pfAnchorCheckResult {
	if p.pfExecBackoffActive() {
		return pfAnchorCheckSkipped
	}
	if !p.pfEnsureRunning.CompareAndSwap(false, true) {
		return pfAnchorCheckSkipped
	}
	defer p.pfEnsureRunning.Store(false)
	return restorePFAnchorForReconcile(p, "tunnel interface change")
}

// checkTunnelInterfaceChanges compares the current set of active tunnel interfaces
// against the last known set. If they differ (e.g., a VPN connected and created utun420),
// it rebuilds and reloads the pf anchor rules to include interface-specific intercept
// rules for the new interface.
//
// Returns true when a new tunnel state is observed or a pending state is
// successfully applied. Coalesced/deferred retries return false so ignored-event
// storms do not bypass the macOS VPN-DNS refresh limiter on every notification.
func (p *prog) checkTunnelInterfaceChanges() bool {
	if p.dnsInterceptState == nil {
		return false
	}

	current := append([]string(nil), discoverTunnelInterfacesForReconcile()...)

	p.mu.Lock()
	prev := append([]string(nil), p.lastTunnelIfaces...)
	stabilizing := p.pfStabilizing.Load()
	newObservation := false
	if p.hasPendingTunnelIfaces && stringSlicesEqual(p.pendingTunnelIfaces, current) {
		if stabilizing {
			p.mu.Unlock()
			return false
		}
		if stringSlicesEqual(prev, current) {
			p.pendingTunnelIfaces = nil
			p.hasPendingTunnelIfaces = false
			p.mu.Unlock()
			return false
		}
		// The same pending state still differs from the applied baseline. Retry it
		// after stabilization/failure instead of treating it as already applied.
	} else {
		if !p.hasPendingTunnelIfaces && stringSlicesEqual(prev, current) {
			p.mu.Unlock()
			return false
		}
		newObservation = true
		p.pendingTunnelIfaces = append([]string(nil), current...)
		p.hasPendingTunnelIfaces = true
	}
	p.mu.Unlock()

	if stringSlicesEqual(prev, current) {
		p.clearPendingTunnelReconcile()
		return true
	}

	// Detect NEW tunnel interfaces (not just any change).
	prevSet := make(map[string]bool, len(prev))
	for _, iface := range prev {
		prevSet[iface] = true
	}
	hasNewTunnel := false
	for _, iface := range current {
		if !prevSet[iface] {
			hasNewTunnel = true
			mainLog.Load().Info().Msgf("DNS intercept: new tunnel interface detected: %s", iface)
			break
		}
	}

	if stabilizing {
		mainLog.Load().Debug().Msgf("DNS intercept: tunnel state changed during stabilization (was %v, now %v) — deferring anchor rebuild", prev, current)
		return newObservation
	}

	if hasNewTunnel {
		// A new VPN tunnel appeared. The dedicated post-stabilization repair path
		// rebuilds the anchor if no successful exemption update applies it first.
		p.pfStartStabilization()
		return newObservation
	}

	mainLog.Load().Info().Msgf("DNS intercept: tunnel interfaces changed (was %v, now %v) — rebuilding pf anchor rules", prev, current)
	result := p.reconcilePFAnchorForTunnelChange()
	if result != pfAnchorCheckRestored {
		// Keep the desired tunnel set pending. The next event, delayed check, or
		// watchdog tick retries it without confusing pending with applied state.
		mainLog.Load().Debug().Msgf("DNS intercept: tunnel rule rebuild deferred/failed (result: %d)", result)
	}
	return newObservation || result == pfAnchorCheckRestored
}

// stringSlicesEqual reports whether two string slices have the same elements in the same order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pfStartStabilization enters stabilization mode, suppressing all pf restores
// until the VPN's ruleset stops changing. This prevents a death spiral where
// ctrld and the VPN repeatedly overwrite each other's pf rules.
func (p *prog) pfStartStabilization() {
	if !p.pfStabilizing.CompareAndSwap(false, true) {
		return
	}

	multiplier := max(int(p.pfBackoffMultiplier.Load()), 1)
	baseStableTime := 6000 * time.Millisecond // 4 polls at 1.5s
	stableRequired := time.Duration(multiplier) * baseStableTime
	if stableRequired > 45*time.Second {
		stableRequired = 45 * time.Second
	}

	mainLog.Load().Info().Msgf("DNS intercept: VPN connecting — entering stabilization mode (waiting %s for pf to settle)", stableRequired)

	ctx, cancel := context.WithCancel(context.Background())
	p.mu.Lock()
	if p.pfStabilizeCancel != nil {
		p.pfStabilizeCancel() // Cancel any previous stabilization
	}
	p.pfStabilizeCancel = cancel
	p.mu.Unlock()

	go p.pfStabilizationLoop(ctx, stableRequired)
}

// pfStabilizationLoop polls pfctl -sr hash until the ruleset is stable for the
// required duration, then restores our anchor rules.
func (p *prog) pfStabilizationLoop(ctx context.Context, stableRequired time.Duration) {
	p.pfStabilizationLoopWithMaxWait(ctx, stableRequired, pfStabilizationMaxWait)
}

func (p *prog) pfStabilizationLoopWithMaxWait(ctx context.Context, stableRequired, maxWaitDuration time.Duration) {
	defer p.pfStabilizing.Store(false)

	pollInterval := 1500 * time.Millisecond
	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()
	maxWait := time.NewTimer(maxWaitDuration)
	defer maxWait.Stop()
	var lastHash string
	stableSince := time.Time{}

	for {
		select {
		case <-ctx.Done():
			mainLog.Load().Debug().Msg("DNS intercept: stabilization cancelled")
			return
		case <-p.stopCh:
			return
		case <-maxWait.C:
			mainLog.Load().Warn().Dur("max_wait", maxWaitDuration).
				Msg("DNS intercept: stabilization timed out — returning ownership to delayed/watchdog recovery")
			p.scheduleDelayedRechecks()
			return
		case <-pollTicker.C:
		}

		if p.pfExecBackoffActive() {
			continue
		}
		// Hash the current filter ruleset.
		out, err := exec.Command("pfctl", "-sr").CombinedOutput()
		if err != nil {
			p.pfBackoffResourceExhaustion(err, out, "poll stabilization filter rules")
			continue
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(out))

		if hash != lastHash {
			// Rules changed — reset stability timer
			lastHash = hash
			stableSince = time.Now()
			mainLog.Load().Debug().Msg("DNS intercept: pf rules changed during stabilization — resetting timer")
			continue
		}

		if stableSince.IsZero() {
			stableSince = time.Now()
			continue
		}

		if time.Since(stableSince) >= stableRequired {
			// The active loop retains ownership until the dedicated post-stable
			// repair finishes. It never re-enters stabilization recursively.
			mainLog.Load().Info().Msgf("DNS intercept: pf stable for %s — reconciling anchor rules", stableRequired)
			result := p.reconcilePFAnchorAfterStabilization()
			if result != pfAnchorCheckRestored && result != pfAnchorCheckIntact {
				p.scheduleDelayedRechecks()
			}
			routes, domainlessServers, exemptions := p.refreshDNSAfterVPNSettle("pf_stabilized")
			if routes == 0 && domainlessServers == 0 && exemptions == 0 {
				p.scheduleDNSAfterVPNSettleRefresh("pf_stabilized_followup", pfAnchorRecheckDelayLong)
			}
			if p.hasPendingTunnelReconcile() {
				p.scheduleDelayedRechecks()
			}
			return
		}
	}
}

var runPFAnchorCheckCommand = func(args ...string) ([]byte, error) {
	return exec.Command("pfctl", args...).CombinedOutput()
}

// ensurePFAnchorActive checks live PF state and returns an explicit outcome for
// callers that must distinguish intact, restored, deferred, skipped, and failed.
func (p *prog) ensurePFAnchorActive() pfAnchorCheckResult {
	return p.ensurePFAnchorActiveWithPolicy(true, false)
}

// reconcilePFAnchorAfterStabilization is owned by the active stabilization loop.
// It bypasses ordinary recent-wipe deferral and forces a rebuild only when tunnel
// state is still pending. Otherwise an intact anchor is left alone, avoiding a
// redundant global PF state flush after an earlier successful exemption update.
func (p *prog) reconcilePFAnchorAfterStabilization() pfAnchorCheckResult {
	return p.ensurePFAnchorActiveWithPolicy(false, p.hasPendingTunnelReconcile())
}

func (p *prog) ensurePFAnchorActiveWithPolicy(allowRecentWipeDeferral, forceRebuild bool) pfAnchorCheckResult {
	if p.dnsInterceptState == nil {
		return pfAnchorCheckSkipped
	}
	// Ordinary callers must not compete with the loop that owns stabilization.
	// Check before acquiring the singleflight guard so the post-stable owner is
	// not blocked by a watchdog callback that would immediately skip.
	if allowRecentWipeDeferral && p.pfStabilizing.Load() {
		mainLog.Load().Debug().Msg("DNS intercept watchdog: suppressed — VPN stabilization in progress")
		return pfAnchorCheckSkipped
	}
	if !p.pfEnsureRunning.CompareAndSwap(false, true) {
		mainLog.Load().Debug().Msg("DNS intercept watchdog: check already running, skipping duplicate")
		return pfAnchorCheckSkipped
	}
	defer p.pfEnsureRunning.Store(false)

	if p.pfExecBackoffActive() {
		return pfAnchorCheckSkipped
	}
	if allowRecentWipeDeferral && p.pfStabilizing.Load() {
		return pfAnchorCheckSkipped
	}

	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)
	needsRestore := false

	// Check 1: anchor references in the main ruleset.
	natOut, err := runPFAnchorCheckCommand("-sn")
	if err != nil {
		p.pfBackoffResourceExhaustion(err, natOut, "dump NAT rules")
		mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump NAT rules")
		return pfAnchorCheckFailed
	}
	natStr := string(natOut)
	if !strings.Contains(natStr, rdrAnchorRef) {
		mainLog.Load().Warn().Msg("DNS intercept watchdog: rdr-anchor reference missing from running ruleset")
		needsRestore = true
	}

	if !needsRestore {
		filterOut, err := runPFAnchorCheckCommand("-sr")
		if err != nil {
			p.pfBackoffResourceExhaustion(err, filterOut, "dump filter rules")
			mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump filter rules")
			return pfAnchorCheckFailed
		}
		if !strings.Contains(string(filterOut), anchorRef) {
			mainLog.Load().Warn().Msg("DNS intercept watchdog: anchor reference missing from running filter rules")
			needsRestore = true
		}
	}

	// Check 2: anchor content (rules inside our anchor).
	// Verify BOTH filter rules (-sr) AND rdr/NAT rules (-sn). Programs like Parallels'
	// internet-sharing can flush our anchor's rdr rules while leaving filter rules intact.
	// Without rdr, route-to sends packets to lo0 but they never get redirected to 127.0.0.1:53,
	// causing an infinite packet loop on lo0 and complete DNS failure.
	if !needsRestore {
		anchorFilter, err := runPFAnchorCheckCommand("-a", pfAnchorName, "-sr")
		if err != nil {
			p.pfBackoffResourceExhaustion(err, anchorFilter, "dump anchor filter rules")
			mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump anchor filter rules")
			return pfAnchorCheckFailed
		}
		if pfRulesetEmpty(string(anchorFilter)) {
			mainLog.Load().Warn().Msg("DNS intercept watchdog: anchor has no filter rules — content was flushed")
			needsRestore = true
		}
	}
	if !needsRestore {
		anchorNat, err := runPFAnchorCheckCommand("-a", pfAnchorName, "-sn")
		if err != nil {
			p.pfBackoffResourceExhaustion(err, anchorNat, "dump anchor NAT rules")
			mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump anchor NAT rules")
			return pfAnchorCheckFailed
		}
		if pfRulesetEmpty(string(anchorNat)) {
			mainLog.Load().Warn().Msg("DNS intercept watchdog: anchor has no rdr rules — translation was flushed (will cause packet loop on lo0)")
			needsRestore = true
		}
	}

	// There is deliberately no "set skip on lo0" check here - see the note in
	// verifyPFState for why macOS cannot be asked for skip state.
	//
	// It matters more here than a missing check might suggest: anything that cannot
	// conclude has to return pfAnchorCheckFailed, and the caller only runs
	// probePFIntercept() and the forced-reload recovery on an intact result. A check
	// that can never conclude would therefore keep this function from ever reporting
	// intact, disabling the functional probe and the self-heal it drives.
	//
	// So the skip case is left to probePFIntercept(). An explicit check can return via
	// "pfctl -s Interfaces -v" once its output shape is confirmed on a host that has a
	// skip configured.

	// Only classify a recent event as a repeated wipe after the live ruleset
	// actually proves that a reference or anchor rule is missing. Previously this
	// timestamp check ran first, so every healthy callback for ten seconds after
	// stabilization was mislabeled as another wipe.
	if lastRestore := p.pfLastRestoreTime.Load(); lastRestore > 0 {
		elapsed := time.Since(time.UnixMilli(lastRestore))
		if needsRestore && allowRecentWipeDeferral && elapsed < 10*time.Second {
			p.pfBackoffMultiplier.Add(1)
			mainLog.Load().Warn().Msgf("DNS intercept: rules wiped %s after restore — entering stabilization (backoff multiplier: %d)",
				elapsed, p.pfBackoffMultiplier.Load())
			p.pfStartStabilization()
			return pfAnchorCheckDeferred
		}
		if elapsed >= 10*time.Second && p.pfBackoffMultiplier.Load() > 0 {
			p.pfBackoffMultiplier.Store(0)
		}
	}

	if !needsRestore && !forceRebuild {
		mainLog.Load().Debug().Msg("DNS intercept watchdog: pf anchor intact")
		return pfAnchorCheckIntact
	}

	reason := "missing pf anchor state"
	if forceRebuild && !needsRestore {
		reason = "post-stabilization rebuild"
	}
	return restorePFAnchorForReconcile(p, reason)
}

// dnsInterceptIgnoredChangeReconcileDue reports whether an ignored macOS
// network delta should run the expensive leading-edge pf/VPN-DNS reconciliation.
// Tunnel changes bypass this decision in the caller. The periodic watchdog and
// coalesced delayed checks remain independent safety nets.
func (p *prog) dnsInterceptIgnoredChangeReconcileDue(now time.Time) bool {
	nowMillis := now.UnixMilli()
	for {
		last := p.pfIgnoredChangeLastReconcile.Load()
		if last > 0 && now.Sub(time.UnixMilli(last)) < pfIgnoredChangeReconcileInterval {
			return false
		}
		if p.pfIgnoredChangeLastReconcile.CompareAndSwap(last, nowMillis) {
			return true
		}
	}
}

func (p *prog) scheduleDNSAfterVPNSettleRefresh(reason string, delay time.Duration) {
	time.AfterFunc(delay, func() {
		if p.dnsInterceptState == nil {
			return
		}
		p.refreshDNSAfterVPNSettle(reason)
	})
}

func (p *prog) pfExecBackoffActive() bool {
	until := p.pfExecBackoffUntil.Load()
	if until == 0 {
		return false
	}
	remaining := time.Until(time.UnixMilli(until))
	if remaining <= 0 {
		p.pfExecBackoffUntil.CompareAndSwap(until, 0)
		return false
	}
	mainLog.Load().Debug().Dur("remaining", remaining).Msg("DNS intercept watchdog: suppressed during pf exec backoff")
	return true
}

func (p *prog) pfBackoffResourceExhaustion(err error, output []byte, operation string) bool {
	if !isResourceExhaustion(err, output) {
		return false
	}
	until := time.Now().Add(pfExecFailureBackoff)
	p.pfExecBackoffUntil.Store(until.UnixMilli())
	mainLog.Load().Warn().Err(err).Dur("backoff", pfExecFailureBackoff).Str("operation", operation).
		Msg("DNS intercept watchdog: backing off after local exec resource exhaustion")
	return true
}

func isResourceExhaustion(err error, output []byte) bool {
	if err == nil && len(output) == 0 {
		return false
	}
	var msg string
	if err != nil {
		msg = err.Error()
	}
	if len(output) > 0 {
		msg += "\n" + string(output)
	}
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "resource temporarily unavailable") ||
		strings.Contains(msg, "too many open files") ||
		strings.Contains(msg, "too many processes") ||
		strings.Contains(msg, "cannot allocate memory")
}

// pfWatchdog periodically checks that our pf anchor is still active.
// Other programs (e.g., Windscribe desktop app, macOS configd) can replace
// scheduleDelayedRechecks schedules delayed re-checks after a network change event.
// VPN apps often modify pf rules and DNS settings asynchronously after the network
// change that triggered our handler. These delayed checks catch:
//   - pf anchor wipes by VPN disconnect (Windscribe's firewallOff)
//   - Stale OS resolver nameservers (VPN DNS not yet cleaned from scutil)
//   - Stale VPN DNS routes in vpnDNSManager
//   - Tunnel interface additions/removals not yet visible
//
// Two delays (2s and 4s) cover both fast and slow VPN teardowns.
func (p *prog) scheduleDelayedRechecks() {
	p.pfDelayedRecheckMu.Lock()
	defer p.pfDelayedRecheckMu.Unlock()

	for _, timer := range p.pfDelayedRecheckTimers {
		if timer != nil {
			timer.Stop()
		}
	}
	p.pfDelayedRecheckTimers = p.pfDelayedRecheckTimers[:0]

	for _, delay := range []time.Duration{pfAnchorRecheckDelay, pfAnchorRecheckDelayLong} {
		delay := delay
		timer := time.AfterFunc(delay, func() {
			if p.dnsInterceptState == nil || p.pfStabilizing.Load() {
				return
			}
			p.ensurePFAnchorActive()
			p.checkTunnelInterfaceChanges()
			// Refresh OS resolver — VPN may have finished DNS cleanup since the
			// immediate handler ran. This clears stale LAN nameservers (e.g.,
			// a VPN's DNS IP (e.g., 10.255.255.3) lingering in scutil --dns).
			ctrld.InitializeOsResolver(true)
			if p.vpnDNS != nil {
				p.vpnDNS.Refresh(true)
			}
		})
		p.pfDelayedRecheckTimers = append(p.pfDelayedRecheckTimers, timer)
	}
}

// the entire pf ruleset with pfctl -f, which wipes our anchor references.
// This watchdog detects and restores them.
func (p *prog) pfWatchdog() {
	mainLog.Load().Info().Msgf("DNS intercept: starting pf watchdog (interval: %s)", pfWatchdogInterval)

	var consecutiveMisses atomic.Int32
	ticker := time.NewTicker(pfWatchdogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			mainLog.Load().Debug().Msg("DNS intercept: pf watchdog stopped")
			return
		case <-ticker.C:
			if p.dnsInterceptState == nil {
				mainLog.Load().Debug().Msg("DNS intercept: pf watchdog exiting — intercept state is nil")
				return
			}

			result := p.ensurePFAnchorActive()
			if result == pfAnchorCheckIntact {
				// Only an authoritative intact result may trigger the functional probe.
				// Skipped/backoff/failed checks must not be treated as healthy text state.
				if !p.pfMonitorRunning.Load() && !p.probePFIntercept() {
					mainLog.Load().Warn().Msg("DNS intercept watchdog: rules intact but probe FAILED — forcing full reload")
					if p.forceReloadPFMainRuleset() {
						result = pfAnchorCheckRestored
					} else {
						result = pfAnchorCheckFailed
					}
				}
			}

			if result == pfAnchorCheckIntact {
				// Check if backoff should be reset only after an authoritative healthy check.
				if p.pfBackoffMultiplier.Load() > 0 && p.pfLastRestoreTime.Load() > 0 {
					elapsed := time.Since(time.UnixMilli(p.pfLastRestoreTime.Load()))
					if elapsed > 60*time.Second {
						p.pfBackoffMultiplier.Store(0)
						mainLog.Load().Info().Msg("DNS intercept watchdog: rules stable for >60s — reset backoff")
					}
				}
			}

			switch result {
			case pfAnchorCheckRestored:
				misses := consecutiveMisses.Add(1)
				if misses >= pfConsecutiveMissThreshold {
					mainLog.Load().Error().Msgf("DNS intercept watchdog: pf anchor has been missing for %d consecutive checks — something is persistently overwriting pf rules", misses)
				} else {
					mainLog.Load().Warn().Msgf("DNS intercept watchdog: pf anchor was missing and restored (consecutive misses: %d)", misses)
				}
			case pfAnchorCheckIntact:
				if old := consecutiveMisses.Swap(0); old > 0 {
					mainLog.Load().Info().Msgf("DNS intercept watchdog: pf anchor stable again after %d consecutive restores", old)
				}
			case pfAnchorCheckSkipped, pfAnchorCheckDeferred, pfAnchorCheckFailed:
				// Preserve the previous authoritative state. Do not probe, count a
				// repair, or reset misses from an indeterminate/deferred result.
			}

			// Tunnel transitions and failed PF/WFP exemption updates are normally
			// event-driven, but the final delayed attempt must remain retryable even
			// if macOS emits no further event.
			tunnelChanged := p.checkTunnelInterfaceChanges()
			pendingExemptions := p.vpnDNS != nil && p.vpnDNS.interceptExemptionsPending()
			// Stabilization owns pf while a VPN's ruleset is still settling, and a
			// refresh rebuilds and reloads the anchor - exactly the mutual overwriting
			// that stabilization exists to stop. Nothing is lost by deferring: the
			// pending tunnel state and pending exemptions both survive, and the next
			// tick retries once stabilization has finished.
			if (tunnelChanged || pendingExemptions) && p.vpnDNS != nil &&
				!p.pfExecBackoffActive() && !p.pfStabilizing.Load() {
				p.vpnDNS.Refresh(true)
			}
		}
	}
}

// exemptVPNDNSServers rebuilds the pf anchor rules to exclude VPN DNS interfaces
// and server IPs from interception. VPN DNS handlers using Network Extensions
// (e.g., Tailscale MagicDNS) need DNS traffic to flow without any pf interference.
//
// Called by vpnDNSManager.Refresh() whenever VPN DNS servers change.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	if p.dnsInterceptState == nil {
		return fmt.Errorf("pf state not available")
	}
	if p.pfExecBackoffActive() {
		return fmt.Errorf("pf exemption update deferred during exec backoff")
	}
	// Defence in depth for the callers guarded at their own call sites: this function
	// rewrites and reloads the whole anchor, which is the mutual overwriting that
	// stabilization suppresses while a VPN's ruleset settles.
	//
	// This does defer handleRecovery's DHCP-nameserver exemption, which has no retry of
	// its own - the trade is deliberate. Those exemptions are ad hoc: they are never
	// registered with the vpnDNSManager, so the post-stabilization reconcile rebuilds
	// the anchor from CurrentExemptions and drops them regardless. Letting them through
	// mid-settle would buy a few seconds of captive-portal access at the cost of the
	// collision stabilization exists to prevent. The error text surfaces in recovery's
	// warning so the reason is visible rather than silent.
	//
	// Manager-driven callers lose nothing: appliedExemptions only advances on success,
	// so interceptExemptionsPending stays true and the next tick retries.
	if p.pfStabilizing.Load() {
		return fmt.Errorf("pf exemption update deferred during stabilization")
	}
	if !p.pfEnsureRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("pf reconciliation already running")
	}
	defer p.pfEnsureRunning.Store(false)

	tunnelIfaces := append([]string(nil), discoverTunnelInterfacesForReconcile()...)
	rulesStr := p.buildPFAnchorRulesForTunnels(exemptions, tunnelIfaces)

	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		return fmt.Errorf("dns intercept: failed to rewrite pf anchor: %w", err)
	}

	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput()
	if err != nil {
		p.pfBackoffResourceExhaustion(err, out, "load VPN DNS anchor")
		return fmt.Errorf("dns intercept: failed to reload pf anchor: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Flush pf states after anchor reload so packets are re-evaluated against new rules.
	// Stale state entries from previous rules would keep routing packets via route-to
	// even after VPN DNS interfaces/IPs are excluded from interception.
	flushPFStates()

	// Ensure the anchor reference still exists in the main ruleset.
	// Another program may have replaced the ruleset since we last checked.
	if err := p.ensurePFAnchorReference(); err != nil {
		p.pfBackoffResourceExhaustion(err, nil, "restore VPN DNS anchor reference")
		p.resetUpstreamTransports()
		return fmt.Errorf("dns intercept: failed to restore anchor reference during VPN DNS update: %w", err)
	}
	p.resetUpstreamTransports()
	p.commitPFReconcileState(tunnelIfaces)

	// Count unique excluded interfaces for logging.
	excludedIfaces := make(map[string]bool)
	for _, ex := range exemptions {
		if ex.Interface != "" {
			excludedIfaces[ex.Interface] = true
		}
	}
	mainLog.Load().Info().Msgf("DNS intercept: updated pf rules — %d VPN DNS servers (%d interfaces excluded from intercept), %d OS resolver servers",
		len(exemptions), len(excludedIfaces), len(ctrld.OsResolverNameservers()))
	return nil
}

// probePFIntercept tests whether pf's rdr translation is actually working by
// sending a DNS query through the interception path from a subprocess that does
// NOT have the _ctrld group GID. If pf interception is working, the query gets
// redirected to 127.0.0.1:53 (ctrld), and the DNS handler signals us. If broken
// (rdr rules present but not evaluating), the query goes to the real DNS server
// and we time out.
//
// Returns true if interception is working, false if broken or indeterminate.
func (p *prog) probePFIntercept() bool {
	if p.dnsInterceptState == nil {
		return true
	}

	nsIPs := ctrld.OsResolverNameservers()
	if len(nsIPs) == 0 {
		mainLog.Load().Debug().Msg("DNS intercept probe: no OS resolver nameservers available")
		return true // can't probe without a target
	}
	host, _, _ := net.SplitHostPort(nsIPs[0])
	if host == "" || host == "127.0.0.1" || host == "::1" {
		mainLog.Load().Debug().Msg("DNS intercept probe: OS resolver is localhost, skipping probe")
		return true // can't probe through localhost
	}

	// Generate unique probe domain
	probeID := fmt.Sprintf("_pf-probe-%x.%s", time.Now().UnixNano()&0xFFFFFFFF, pfProbeDomain)

	// Register this attempt's own domain: overlapping probes must not cancel each other.
	probeCh, deregister := p.registerInterceptProbe(probeID)
	defer deregister()

	// Build a minimal DNS query packet for the probe domain.
	// We use exec.Command to send from a subprocess with GID=0 (wheel),
	// so pf's _ctrld group exemption does NOT apply and the query gets intercepted.
	dnsPacket := buildDNSQueryPacket(probeID)

	// Send via a helper subprocess that drops the _ctrld group
	cmd := exec.Command(os.Args[0], "pf-probe-send", host, fmt.Sprintf("%x", dnsPacket))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0, // wheel group — NOT _ctrld, so pf intercepts it
		},
	}

	if err := cmd.Start(); err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept probe: failed to start probe subprocess")
		return true // can't probe, assume OK
	}

	// Don't leak the subprocess
	go func() {
		_ = cmd.Wait()
	}()

	select {
	case <-probeCh:
		return true
	case <-time.After(pfProbeTimeout):
		return false
	}
}

// buildDNSQueryPacket constructs a minimal DNS query packet (wire format) for the given domain.
func buildDNSQueryPacket(domain string) []byte {
	// DNS header: ID=0x1234, QR=0, OPCODE=0, RD=1, QDCOUNT=1
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	}

	// Encode domain name in DNS wire format (label-length encoding)
	// Remove trailing dot if present
	d := strings.TrimSuffix(domain, ".")
	var qname []byte
	for _, label := range strings.Split(d, ".") {
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // root label

	// QTYPE=A (1), QCLASS=IN (1)
	question := append(qname, 0x00, 0x01, 0x00, 0x01)

	return append(header, question...)
}

// pfInterceptMonitor runs asynchronously after interface changes are detected.
// It probes pf interception with exponential backoff and forces a full pf reload
// if the probe fails. Only one instance runs at a time (singleton via atomic.Bool).
//
// The backoff schedule provides both fast detection (immediate + 500ms) and extended
// coverage (up to ~8s) to win the race against async pf reloads by hypervisors.
func (p *prog) pfInterceptMonitor() {
	if !p.pfMonitorRunning.CompareAndSwap(false, true) {
		mainLog.Load().Debug().Msg("DNS intercept monitor: already running, skipping")
		return
	}
	defer p.pfMonitorRunning.Store(false)

	mainLog.Load().Info().Msg("DNS intercept monitor: starting interception probe sequence")

	// Backoff schedule: probe quickly first, then space out.
	// Total monitoring window: ~0 + 0.5 + 1 + 2 + 4 = ~7.5s
	delays := []time.Duration{0, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}

	for i, delay := range delays {
		if delay > 0 {
			time.Sleep(delay)
		}
		if p.dnsInterceptState == nil || p.pfStabilizing.Load() {
			mainLog.Load().Debug().Msg("DNS intercept monitor: aborting — intercept disabled or stabilizing")
			return
		}

		if p.probePFIntercept() {
			mainLog.Load().Debug().Msgf("DNS intercept monitor: probe %d/%d passed", i+1, len(delays))
			continue // working now — keep monitoring in case it breaks later in the window
		}

		// Probe failed — pf translation is broken. Force full reload.
		mainLog.Load().Warn().Msgf("DNS intercept monitor: probe %d/%d FAILED — pf translation broken, forcing full ruleset reload", i+1, len(delays))
		p.forceReloadPFMainRuleset()

		// Verify the reload fixed it
		time.Sleep(200 * time.Millisecond)
		if p.probePFIntercept() {
			mainLog.Load().Info().Msg("DNS intercept monitor: probe passed after reload — interception restored")
			// Continue monitoring in case the hypervisor reloads pf again
		} else {
			mainLog.Load().Error().Msg("DNS intercept monitor: probe still failing after reload — pf may need manual intervention")
		}
	}

	mainLog.Load().Info().Msg("DNS intercept monitor: probe sequence completed")
}

// forceReloadPFMainRuleset unconditionally reloads the entire pf ruleset via
// "pfctl -f -". This resets pf's internal translation engine, fixing cases where
// rdr rules exist in text form but aren't being evaluated (e.g., after a hypervisor
// like Parallels reloads /etc/pf.conf as a side effect of creating/destroying
// virtual network interfaces).
//
// Unlike ensurePFAnchorReference() which returns early when anchor references are
// already present, this function always performs the full reload.
//
// The reload is safe for VPN interop because it reassembles from the current running
// ruleset (pfctl -sr/-sn), preserving all existing anchors and rules.
func (p *prog) forceReloadPFMainRuleset() bool {
	if p.dnsInterceptState == nil || p.pfExecBackoffActive() {
		return false
	}
	if !p.pfEnsureRunning.CompareAndSwap(false, true) {
		return false
	}
	defer p.pfEnsureRunning.Store(false)

	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	// Dump running rules.
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: force reload — failed to dump NAT rules")
		return false
	}

	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: force reload — failed to dump filter rules")
		return false
	}

	natLines := pfFilterRuleLines(string(natOut))
	filterLines := pfFilterRuleLines(string(filterOut))

	// Separate scrub rules from filter rules.
	var scrubLines, pureFilterLines []string
	for _, line := range filterLines {
		if strings.HasPrefix(line, "scrub") {
			scrubLines = append(scrubLines, line)
		} else {
			pureFilterLines = append(pureFilterLines, line)
		}
	}

	// Ensure our anchor references are present (they may have been wiped).
	if !pfContainsRule(natLines, rdrAnchorRef) {
		natLines = append([]string{rdrAnchorRef}, natLines...)
	}
	if !pfContainsRule(pureFilterLines, anchorRef) {
		pureFilterLines = append([]string{anchorRef}, pureFilterLines...)
	}

	// Reassemble in pf's required order: scrub → translation → filtering. As in
	// ensurePFAnchorReference, no options section is emitted; see the KNOWN GAP note
	// there.
	var combined strings.Builder
	for _, line := range scrubLines {
		combined.WriteString(line + "\n")
	}
	for _, line := range natLines {
		combined.WriteString(line + "\n")
	}
	for _, line := range pureFilterLines {
		combined.WriteString(line + "\n")
	}

	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(combined.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msgf("DNS intercept: force reload — pfctl -f - failed (output: %s)", strings.TrimSpace(string(out)))
		return false
	}
	// A successful main ruleset reload invalidates PF state even if the
	// subsequent anchor rebuild fails, so retire stale DoH transports now.
	p.resetUpstreamTransports()

	if result := p.restorePFAnchorWithTransportReset("forced main ruleset reload", false); result != pfAnchorCheckRestored {
		mainLog.Load().Error().Msg("DNS intercept: force reload — anchor rebuild failed")
		return false
	}

	mainLog.Load().Info().Msg("DNS intercept: force reload — pf ruleset and anchor reloaded successfully")
	return true
}

// osHealthcheckSuppressed always returns false on darwin — WFP loopback
// protect (the trigger for suppression) is Windows-only.
func (p *prog) osHealthcheckSuppressed() bool { return false }

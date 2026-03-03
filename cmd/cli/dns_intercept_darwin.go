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
	// exemptions, causing queries to be intercepted and routed to ctrld. Stale pf
	// state entries from the gap persist even after vpnDNS.Refresh() adds exemptions.
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
		os.Remove(pfAnchorFile)
		return fmt.Errorf("dns intercept: failed to load pf anchor: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	mainLog.Load().Debug().Msgf("DNS intercept: loaded pf anchor %q from %s", pfAnchorName, pfAnchorFile)

	if err := p.ensurePFAnchorReference(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: could not add anchor references to running pf ruleset — anchor may not be active")
	}

	out, err = exec.Command("pfctl", "-e").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if !strings.Contains(outStr, "already enabled") {
			mainLog.Load().Warn().Msgf("DNS intercept: pfctl -e returned: %s (err: %v) — pf may not be enabled", outStr, err)
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

	// Post-load verification: confirm everything actually took effect.
	p.verifyPFState()

	p.dnsInterceptState = &pfState{
		anchorFile: pfAnchorFile,
		anchorName: pfAnchorName,
	}

	// Store the initial set of tunnel interfaces so we can detect changes later.
	p.mu.Lock()
	p.lastTunnelIfaces = discoverTunnelInterfaces()
	p.mu.Unlock()

	mainLog.Load().Info().Msgf("DNS intercept: pf redirect active — all outbound DNS (port 53) redirected to 127.0.0.1:53 via anchor %q", pfAnchorName)

	// Start the pf watchdog to detect and restore rules if another program
	// (e.g., Windscribe desktop, macOS configd) replaces the pf ruleset.
	go p.pfWatchdog()

	return nil
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
// "pfctl -sn" returns nat-anchor AND rdr-anchor (translation) rules.
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
	// "windscribe_vpn_traffic"). pf evaluates rules top-to-bottom, so "quick"
	// rules in whichever anchor appears first win. By prepending, our DNS
	// intercept rules match port 53 traffic before a VPN app's broader
	// "pass out quick on <iface> all" rules in their anchor.
	if !hasRdrAnchor {
		natLines = append([]string{rdrAnchorRef}, natLines...)
	}
	if !hasAnchor {
		pureFilterLines = append([]string{anchorRef}, pureFilterLines...)
	}

	// Dump and clean pf options. VPN apps (e.g., Windscribe) set "set skip on { lo0 }"
	// which disables pf processing on loopback, breaking our route-to + rdr mechanism.
	// We strip lo0 and tunnel interfaces from the skip list before reloading.
	cleanedOptions, hadLoopbackSkip := pfGetCleanedOptions()
	if hadLoopbackSkip {
		mainLog.Load().Info().Msg("DNS intercept: will reload pf options without lo0 in skip list")
	}

	// Reassemble in pf's required order: options → scrub → translation → filtering.
	var combined strings.Builder
	if cleanedOptions != "" {
		combined.WriteString(cleanedOptions)
	}
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
// "windscribe_vpn_traffic") appears before ours, its "quick" rules may match
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

// pfGetCleanedOptions dumps the running pf options via "pfctl -sO" and returns
// them with lo0 removed from any "set skip on" directive. VPN apps like Windscribe
// set "set skip on { lo0 <vpn_iface> }" which tells pf to bypass ALL processing on
// loopback — this breaks our route-to + rdr interception mechanism which depends on
// lo0. We strip lo0 (and any known VPN tunnel interfaces) from the skip list so our
// rdr rules on lo0 can fire. Other options (timeouts, limits, etc.) are preserved.
//
// Returns the cleaned options as a string suitable for prepending to a pfctl -f reload,
// and a boolean indicating whether lo0 was found in the skip list (i.e., we needed to fix it).
func pfGetCleanedOptions() (string, bool) {
	out, err := exec.Command("pfctl", "-sO").CombinedOutput()
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("DNS intercept: could not dump pf options")
		return "", false
	}

	var cleaned strings.Builder
	hadLoopbackSkip := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "ALTQ") {
			continue
		}

		// Parse "set skip on { lo0 ipsec0 }" or "set skip on lo0"
		if strings.HasPrefix(line, "set skip on") {
			// Extract interface list from the skip directive.
			skipPart := strings.TrimPrefix(line, "set skip on")
			skipPart = strings.TrimSpace(skipPart)
			skipPart = strings.Trim(skipPart, "{}")
			skipPart = strings.TrimSpace(skipPart)

			ifaces := strings.Fields(skipPart)
			var kept []string
			for _, iface := range ifaces {
				if iface == "lo0" {
					hadLoopbackSkip = true
					continue // Remove lo0 — we need pf to process lo0 for our rdr rules.
				}
				// Also remove VPN tunnel interfaces — we have explicit intercept
				// rules for them in our anchor, so skipping defeats the purpose.
				isTunnel := false
				for _, prefix := range strings.Split(pfVPNInterfacePrefixes, ",") {
					if strings.HasPrefix(iface, strings.TrimSpace(prefix)) {
						isTunnel = true
						break
					}
				}
				if isTunnel {
					mainLog.Load().Debug().Msgf("DNS intercept: removing tunnel interface %q from pf skip list", iface)
					continue
				}
				kept = append(kept, iface)
			}

			if len(kept) > 0 {
				cleaned.WriteString(fmt.Sprintf("set skip on { %s }\n", strings.Join(kept, " ")))
			}
			// If no interfaces left, omit the skip directive entirely.
			continue
		}

		// Preserve all other options (timeouts, limits, etc.).
		cleaned.WriteString(line + "\n")
	}

	if hadLoopbackSkip {
		mainLog.Load().Warn().Msg("DNS intercept: detected 'set skip on lo0' — another program (likely VPN software) " +
			"disabled pf processing on loopback, which breaks our DNS interception. Removing lo0 from skip list.")
	}

	return cleaned.String(), hadLoopbackSkip
}

// pfFilterRuleLines filters pfctl output into actual pf rule lines,
// stripping stderr warnings (e.g., "No ALTQ support in kernel") and empty lines.
func pfFilterRuleLines(output string) []string {
	var rules []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip pfctl stderr warnings that appear in CombinedOutput.
		if strings.Contains(line, "ALTQ") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

// pfContainsRule checks if any line in the slice contains the given rule string.
// Uses substring matching because pfctl may append extra tokens like " all" to rules
// (e.g., `rdr-anchor "com.controld.ctrld" all`), which would fail exact matching.
func pfContainsRule(lines []string, rule string) bool {
	for _, line := range lines {
		if strings.Contains(line, rule) {
			return true
		}
	}
	return false
}

// stopDNSIntercept removes all pf rules and cleans up the DNS interception.
func (p *prog) stopDNSIntercept() error {
	if p.dnsInterceptState == nil {
		mainLog.Load().Debug().Msg("DNS intercept: no pf state to clean up")
		return nil
	}

	mainLog.Load().Info().Msg("DNS intercept: shutting down pf redirect")

	out, err := exec.Command("pfctl", "-a", p.dnsInterceptState.(*pfState).anchorName, "-F", "all").CombinedOutput()
	if err != nil {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to flush pf anchor %q: %v (output: %s)",
			p.dnsInterceptState.(*pfState).anchorName, err, strings.TrimSpace(string(out)))
	} else {
		mainLog.Load().Debug().Msgf("DNS intercept: flushed pf anchor %q", p.dnsInterceptState.(*pfState).anchorName)
	}

	if err := os.Remove(p.dnsInterceptState.(*pfState).anchorFile); err != nil && !os.IsNotExist(err) {
		mainLog.Load().Warn().Msgf("DNS intercept: failed to remove anchor file %s: %v", p.dnsInterceptState.(*pfState).anchorFile, err)
	} else {
		mainLog.Load().Debug().Msgf("DNS intercept: removed anchor file %s", p.dnsInterceptState.(*pfState).anchorFile)
	}

	if err := p.removePFAnchorReference(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to remove anchor references from running pf ruleset")
	}

	p.dnsInterceptState = nil
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
// flushPFStates flushes ALL pf state entries after anchor reloads.
// pf checks state table BEFORE rules — stale entries from old rules keep routing
// packets via route-to even after interface-scoped exemptions are added.
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
	var rules strings.Builder
	rules.WriteString("# ctrld DNS Intercept Mode\n")
	rules.WriteString("# Intercepts locally-originated DNS (port 53) via route-to + rdr on lo0.\n")
	rules.WriteString("#\n")
	rules.WriteString("# How it works:\n")
	rules.WriteString("#   1. \"pass out route-to lo0\" forces outbound DNS through the loopback interface\n")
	rules.WriteString("#   2. \"rdr on lo0\" catches it on loopback and redirects to ctrld at 127.0.0.1:53\n")
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
	rules.WriteString("# Redirect DNS traffic arriving on loopback (from route-to) to ctrld's listener.\n")
	rules.WriteString("# Uses rdr (not rdr pass) — filter rules must evaluate to create response state.\n")
	rules.WriteString("rdr on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53\n")
	rules.WriteString("rdr on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53\n\n")

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
	// EXIT MODE EXCEPTION: When a VPN is in exit/full-tunnel mode (VPN DNS server is
	// also the system default resolver), we do NOT exempt the interface. In exit mode,
	// all traffic routes through the VPN, so exempting the interface would bypass ctrld
	// for ALL DNS — losing profile enforcement (blocking, filtering). Instead, we keep
	// intercepting and let ctrld's VPN DNS split routing + group exemption handle it.
	vpnDNSIfaces := make(map[string]bool)           // non-exit interfaces to skip in tunnel intercept
	vpnDNSIfacePassthrough := make(map[string]bool) // non-exit interfaces needing passthrough rules
	vpnDNSServerIPs := make(map[string]bool)        // IPs for group exemptions and <vpn_dns> table
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

	// Block all outbound IPv6 DNS. ctrld only listens on 0.0.0.0:53 (IPv4), so we cannot
	// redirect IPv6 DNS to our listener. Without this rule, macOS may use IPv6 link-local
	// DNS servers (e.g., fe80::...%en0) assigned by the router, completely bypassing the
	// IPv4 pf intercept. Blocking forces macOS to fall back to IPv4 DNS, which is intercepted.
	// This rule must come BEFORE the IPv4 route-to rules (pf evaluates last match by default,
	// but "quick" makes first-match — and exemptions above are already "quick").
	rules.WriteString("# Block outbound IPv6 DNS — ctrld listens on IPv4 only (0.0.0.0:53).\n")
	rules.WriteString("# Without this, macOS may use IPv6 link-local DNS servers from the router,\n")
	rules.WriteString("# bypassing the IPv4 intercept entirely.\n")
	rules.WriteString("block out quick on ! lo0 inet6 proto { udp, tcp } from any to any port 53\n\n")

	// --- VPN DNS interface passthrough (split DNS mode only) ---
	//
	// In split DNS mode, the VPN's DNS handler (e.g., Tailscale MagicDNS) runs as a
	// Network Extension that intercepts packets on its tunnel interface. MagicDNS then
	// forwards queries to its own upstream nameservers (e.g., 10.3.112.11) — IPs we
	// can't know in advance. Without these rules, pf's generic "on !lo0" intercept
	// catches MagicDNS's upstream queries, routing them back to ctrld in a loop.
	//
	// These "pass" rules (no route-to) let MagicDNS's upstream queries pass through.
	// Traffic TO the VPN DNS server (e.g., 100.100.100.100) is excluded via <vpn_dns>
	// so those queries get intercepted → ctrld enforces its profile on non-search-domain queries.
	//
	// NOT applied in exit mode — in exit mode, all traffic routes through the VPN
	// interface, so exempting it would bypass ctrld's profile enforcement entirely.
	if len(vpnDNSIfacePassthrough) > 0 {
		// Build table of VPN DNS server IPs to exclude from passthrough.
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
	tunnelIfaces := discoverTunnelInterfaces()
	if len(tunnelIfaces) > 0 {
		rules.WriteString("# --- VPN/tunnel interface intercept rules ---\n")
		rules.WriteString("# Explicit intercept on tunnel interfaces prevents VPN apps from capturing\n")
		rules.WriteString("# DNS traffic with their own broad \"pass out quick on <iface>\" rules.\n")
		rules.WriteString("# VPN DNS interfaces (split DNS mode) are excluded — passthrough rules above handle them.\n")
		for _, iface := range tunnelIfaces {
			if vpnDNSIfaces[iface] {
				rules.WriteString(fmt.Sprintf("# Skipped %s — VPN DNS interface (passthrough rules handle this)\n", iface))
				continue
			}
			rules.WriteString(fmt.Sprintf("pass out quick on %s route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53\n", iface))
			rules.WriteString(fmt.Sprintf("pass out quick on %s route-to lo0 inet proto tcp from any to ! 127.0.0.1 port 53\n", iface))
		}
		rules.WriteString("\n")
	}

	// Force all remaining outbound IPv4 DNS through loopback for interception.
	// route-to rules use stateful tracking (keep state, the default). State is floating
	// (matches on any interface), but "pass out on lo0 no state" below ensures no state
	// is created on the lo0 outbound path, allowing rdr to fire on lo0 inbound.
	rules.WriteString("# Force remaining outbound IPv4 DNS through loopback for interception.\n")
	rules.WriteString("pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53\n")
	rules.WriteString("pass out quick on ! lo0 route-to lo0 inet proto tcp from any to ! 127.0.0.1 port 53\n\n")

	// Allow route-to'd DNS packets to pass outbound on lo0.
	// Without this, VPN firewalls with "block drop all" (e.g., Windscribe) drop the packet
	// after route-to redirects it to lo0 but before it can reflect inbound for rdr processing.
	//
	// CRITICAL: This rule MUST use "no state". If it created state, that state would match
	// the packet when it reflects inbound on lo0, causing pf to fast-path it and bypass
	// rdr entirely. With "no state", the inbound packet gets fresh evaluation and rdr fires.
	rules.WriteString("# Pass route-to'd DNS outbound on lo0 — no state to avoid bypassing rdr inbound.\n")
	rules.WriteString("pass out quick on lo0 inet proto udp from any to ! 127.0.0.1 port 53 no state\n")
	rules.WriteString("pass out quick on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 no state\n\n")

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
	rules.WriteString("pass in quick on lo0 reply-to lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53\n")

	return rules.String()
}

// verifyPFState checks that the pf ruleset is correctly configured after loading.
// It verifies both the anchor references in the main ruleset and the rules within
// our anchor. Failures are logged at ERROR level to make them impossible to miss.
func (p *prog) verifyPFState() {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)
	verified := true

	// Check main ruleset for anchor references.
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump NAT rules")
		verified = false
	} else if !strings.Contains(string(natOut), rdrAnchorRef) {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — rdr-anchor reference missing from running NAT rules")
		verified = false
	}

	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump filter rules")
		verified = false
	} else if !strings.Contains(string(filterOut), anchorRef) {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor reference missing from running filter rules")
		verified = false
	}

	// Check our anchor has rules loaded.
	anchorFilter, err := exec.Command("pfctl", "-a", pfAnchorName, "-sr").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump anchor filter rules")
		verified = false
	} else if len(strings.TrimSpace(string(anchorFilter))) == 0 {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor has no filter rules loaded")
		verified = false
	}

	anchorNat, err := exec.Command("pfctl", "-a", pfAnchorName, "-sn").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: VERIFICATION FAILED — could not dump anchor NAT rules")
		verified = false
	} else if len(strings.TrimSpace(string(anchorNat))) == 0 {
		mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — anchor has no NAT/redirect rules loaded")
		verified = false
	}

	// Check that lo0 is not in the skip list — if it is, our rdr rules are dead.
	optOut, err := exec.Command("pfctl", "-sO").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(optOut), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "set skip on") && strings.Contains(line, "lo0") {
				mainLog.Load().Error().Msg("DNS intercept: VERIFICATION FAILED — 'set skip on lo0' is active, rdr rules on loopback will not fire")
				verified = false
				break
			}
		}
	}

	if verified {
		mainLog.Load().Info().Msg("DNS intercept: post-load verification passed — all pf rules confirmed active")
	}
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
		uc.ForceReBootstrap(ctrld.LoggerCtx(context.Background(), p.logger.Load()))
		count++
	}
	if count > 0 {
		mainLog.Load().Info().Msgf("DNS intercept watchdog: force-reset %d upstream transport(s) — pf state flush likely killed existing DoH connections", count)
	}
}

// checkTunnelInterfaceChanges compares the current set of active tunnel interfaces
// against the last known set. If they differ (e.g., a VPN connected and created utun420),
// it rebuilds and reloads the pf anchor rules to include interface-specific intercept
// rules for the new interface.
//
// Returns true if the anchor was rebuilt, false if no changes detected.
// This is called from the network change callback even when validInterfacesMap()
// reports no changes — because validInterfacesMap() only tracks physical hardware
// ports (en0, bridge0, etc.) and ignores tunnel interfaces (utun*, ipsec*, etc.).
func (p *prog) checkTunnelInterfaceChanges() bool {
	if p.dnsInterceptState == nil {
		return false
	}

	current := discoverTunnelInterfaces()

	p.mu.Lock()
	prev := p.lastTunnelIfaces
	changed := !stringSlicesEqual(prev, current)
	if changed {
		p.lastTunnelIfaces = current
	}
	p.mu.Unlock()

	if !changed {
		return false
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

	if hasNewTunnel {
		// A new VPN tunnel appeared. Enter stabilization mode — the VPN may be
		// about to wipe our pf rules (Windscribe does this ~500ms after tunnel creation).
		// We can't check pfAnchorIsWiped() here because the wipe hasn't happened yet.
		// The stabilization loop will detect whether pf actually gets wiped:
		// - If rules change (VPN touches pf): wait for stability, then restore.
		// - If rules stay stable for the full wait (Tailscale): exit early and rebuild immediately.
		p.pfStartStabilization()
		return true
	}

	mainLog.Load().Info().Msgf("DNS intercept: tunnel interfaces changed (was %v, now %v) — rebuilding pf anchor rules", prev, current)

	// Rebuild anchor rules with the updated tunnel interface list.
	// Pass current VPN DNS exemptions so they are preserved for still-active VPNs.
	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRules(vpnExemptions)
	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: failed to write rebuilt anchor file")
		return true
	}
	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msgf("DNS intercept: failed to reload rebuilt anchor (output: %s)", strings.TrimSpace(string(out)))
		return true
	}

	flushPFStates()
	mainLog.Load().Info().Msgf("DNS intercept: rebuilt pf anchor with %d tunnel interfaces", len(current))
	return true
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
	if p.pfStabilizing.Load() {
		// Already stabilizing — extending is handled by backoff.
		return
	}
	p.pfStabilizing.Store(true)

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
	defer p.pfStabilizing.Store(false)

	pollInterval := 1500 * time.Millisecond
	var lastHash string
	stableSince := time.Time{}

	for {
		select {
		case <-ctx.Done():
			mainLog.Load().Debug().Msg("DNS intercept: stabilization cancelled")
			return
		case <-p.stopCh:
			return
		case <-time.After(pollInterval):
		}

		// Hash the current filter ruleset.
		out, err := exec.Command("pfctl", "-sr").CombinedOutput()
		if err != nil {
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
			// Stable long enough — restore our rules.
			// Clear stabilizing flag BEFORE calling ensurePFAnchorActive so
			// the guard inside that function doesn't suppress our restore.
			p.pfStabilizing.Store(false)
			mainLog.Load().Info().Msgf("DNS intercept: pf stable for %s — restoring anchor rules", stableRequired)
			p.ensurePFAnchorActive()
			p.pfLastRestoreTime.Store(time.Now().UnixMilli())
			return
		}
	}
}

// ensurePFAnchorActive checks that our pf anchor references and rules are still
// present in the running ruleset. If anything is missing (e.g., another program
// like Windscribe desktop or macOS itself reloaded pf.conf), it restores them.
//
// Returns true if restoration was needed, false if everything was already intact.
// Called both on network changes (immediate) and by the periodic pfWatchdog.
func (p *prog) ensurePFAnchorActive() bool {
	if p.dnsInterceptState == nil {
		return false
	}

	// While stabilizing (VPN connecting), suppress all restores.
	// The stabilization loop will restore once pf settles.
	if p.pfStabilizing.Load() {
		mainLog.Load().Debug().Msg("DNS intercept watchdog: suppressed — VPN stabilization in progress")
		return false
	}

	// Check if our last restore was very recent and got wiped again.
	// This indicates a VPN reconnect cycle — enter stabilization with backoff.
	if lastRestore := p.pfLastRestoreTime.Load(); lastRestore > 0 {
		elapsed := time.Since(time.UnixMilli(lastRestore))
		if elapsed < 10*time.Second {
			// Rules were wiped within 10s of our last restore — VPN is fighting us.
			p.pfBackoffMultiplier.Add(1)
			mainLog.Load().Warn().Msgf("DNS intercept: rules wiped %s after restore — entering stabilization (backoff multiplier: %d)",
				elapsed, p.pfBackoffMultiplier.Load())
			p.pfStartStabilization()
			return false
		}
		// Rules survived >10s — reset backoff
		if p.pfBackoffMultiplier.Load() > 0 {
			p.pfBackoffMultiplier.Store(0)
		}
	}

	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)
	needsRestore := false

	// Check 1: anchor references in the main ruleset.
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump NAT rules")
		return false
	}
	if !strings.Contains(string(natOut), rdrAnchorRef) {
		mainLog.Load().Warn().Msg("DNS intercept watchdog: rdr-anchor reference missing from running ruleset")
		needsRestore = true
	}

	if !needsRestore {
		filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
		if err != nil {
			mainLog.Load().Warn().Err(err).Msg("DNS intercept watchdog: could not dump filter rules")
			return false
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
		anchorFilter, err := exec.Command("pfctl", "-a", pfAnchorName, "-sr").CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(anchorFilter))) == 0 {
			mainLog.Load().Warn().Msg("DNS intercept watchdog: anchor has no filter rules — content was flushed")
			needsRestore = true
		}
	}
	if !needsRestore {
		anchorNat, err := exec.Command("pfctl", "-a", pfAnchorName, "-sn").CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(anchorNat))) == 0 {
			mainLog.Load().Warn().Msg("DNS intercept watchdog: anchor has no rdr rules — translation was flushed (will cause packet loop on lo0)")
			needsRestore = true
		}
	}

	// Check 3: "set skip on lo0" — VPN apps (e.g., Windscribe) load a complete pf.conf
	// with "set skip on { lo0 <vpn_iface> }" which disables ALL pf processing on loopback.
	// Our entire interception mechanism (route-to lo0 + rdr on lo0) depends on lo0 being
	// processed by pf. This check detects the skip and triggers a restore that removes it.
	if !needsRestore {
		optOut, err := exec.Command("pfctl", "-sO").CombinedOutput()
		if err == nil {
			optStr := string(optOut)
			// Check if lo0 appears in any "set skip on" directive.
			for _, line := range strings.Split(optStr, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "set skip on") && strings.Contains(line, "lo0") {
					mainLog.Load().Warn().Msg("DNS intercept watchdog: 'set skip on lo0' detected — loopback bypass breaks our rdr rules")
					needsRestore = true
					break
				}
			}
		}
	}

	if !needsRestore {
		mainLog.Load().Debug().Msg("DNS intercept watchdog: pf anchor intact")
		return false
	}

	// Restore: re-inject anchor references into the main ruleset.
	mainLog.Load().Info().Msg("DNS intercept watchdog: restoring pf anchor references")
	if err := p.ensurePFAnchorReference(); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept watchdog: failed to restore anchor references")
		return true
	}

	// Restore: always rebuild anchor rules from scratch to ensure tunnel interface
	// rules are up-to-date (VPN interfaces may have appeared/disappeared since the
	// anchor file was last written).
	mainLog.Load().Info().Msg("DNS intercept watchdog: rebuilding anchor rules with current network state")
	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRules(vpnExemptions)
	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept watchdog: failed to write anchor file")
	} else if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("DNS intercept watchdog: failed to load rebuilt anchor (output: %s)", strings.TrimSpace(string(out)))
	} else {
		flushPFStates()
		mainLog.Load().Info().Msg("DNS intercept watchdog: rebuilt and loaded anchor rules")
	}

	// Update tracked tunnel interfaces after rebuild so checkTunnelInterfaceChanges()
	// has an accurate baseline for subsequent comparisons.
	p.mu.Lock()
	p.lastTunnelIfaces = discoverTunnelInterfaces()
	p.mu.Unlock()

	// Verify the restoration worked.
	p.verifyPFState()

	// Proactively reset upstream transports. When another program replaces the pf
	// ruleset with "pfctl -f", it flushes the entire state table — killing all
	// existing TCP connections including our DoH connections to upstream DNS servers.
	// Without this reset, Go's http.Transport keeps trying dead connections until
	// the 5s context deadline, causing a DNS blackout. Re-bootstrapping forces fresh
	// TLS handshakes on the next query (~200ms vs ~5s recovery).
	p.resetUpstreamTransports()

	p.pfLastRestoreTime.Store(time.Now().UnixMilli())
	mainLog.Load().Info().Msg("DNS intercept watchdog: pf anchor restored successfully")
	return true
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
	for _, delay := range []time.Duration{pfAnchorRecheckDelay, pfAnchorRecheckDelayLong} {
		time.AfterFunc(delay, func() {
			if p.dnsInterceptState == nil || p.pfStabilizing.Load() {
				return
			}
			p.ensurePFAnchorActive()
			p.checkTunnelInterfaceChanges()
			// Refresh OS resolver — VPN may have finished DNS cleanup since the
			// immediate handler ran. This clears stale LAN nameservers (e.g.,
			// Windscribe's 10.255.255.3 lingering in scutil --dns).
			ctx := ctrld.LoggerCtx(context.Background(), p.logger.Load())
			ctrld.InitializeOsResolver(ctx, true)
			if p.vpnDNS != nil {
				p.vpnDNS.Refresh(ctx)
			}
		})
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

			restored := p.ensurePFAnchorActive()
			if !restored {
				// Rules are intact in text form — also probe actual interception.
				if !p.pfStabilizing.Load() && !p.pfMonitorRunning.Load() {
					if !p.probePFIntercept() {
						mainLog.Load().Warn().Msg("DNS intercept watchdog: rules intact but probe FAILED — forcing full reload")
						p.forceReloadPFMainRuleset()
						restored = true
					}
				}

				// Check if backoff should be reset.
				if p.pfBackoffMultiplier.Load() > 0 && p.pfLastRestoreTime.Load() > 0 {
					elapsed := time.Since(time.UnixMilli(p.pfLastRestoreTime.Load()))
					if elapsed > 60*time.Second {
						p.pfBackoffMultiplier.Store(0)
						mainLog.Load().Info().Msg("DNS intercept watchdog: rules stable for >60s — reset backoff")
					}
				}
			}
			if restored {
				misses := consecutiveMisses.Add(1)
				if misses >= pfConsecutiveMissThreshold {
					mainLog.Load().Error().Msgf("DNS intercept watchdog: pf anchor has been missing for %d consecutive checks — something is persistently overwriting pf rules", misses)
				} else {
					mainLog.Load().Warn().Msgf("DNS intercept watchdog: pf anchor was missing and restored (consecutive misses: %d)", misses)
				}
			} else {
				if old := consecutiveMisses.Swap(0); old > 0 {
					mainLog.Load().Info().Msgf("DNS intercept watchdog: pf anchor stable again after %d consecutive restores", old)
				}
			}
		}
	}
}

// exemptVPNDNSServers updates the pf anchor rules with interface-scoped exemptions
// for VPN DNS servers, allowing VPN local DNS handlers (e.g., Tailscale MagicDNS
// via Network Extension) to receive DNS queries from all processes on their interface.
//
// Called by vpnDNSManager.Refresh() whenever VPN DNS servers change.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	if p.dnsInterceptState == nil {
		return fmt.Errorf("pf state not available")
	}

	rulesStr := p.buildPFAnchorRules(exemptions)

	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		return fmt.Errorf("dns intercept: failed to rewrite pf anchor: %w", err)
	}

	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("dns intercept: failed to reload pf anchor: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Flush stale pf states so packets are re-evaluated against new rules.
	flushPFStates()

	// Ensure the anchor reference still exists in the main ruleset.
	// Another program may have replaced the ruleset since we last checked.
	if err := p.ensurePFAnchorReference(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("DNS intercept: failed to verify anchor reference during VPN DNS update")
	}

	mainLog.Load().Info().Msgf("DNS intercept: updated pf rules — exempted %d VPN DNS + %d OS resolver servers",
		len(exemptions), len(ctrld.OsResolverNameservers()))
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

	// Register probe so DNS handler can detect and signal it
	probeCh := make(chan struct{}, 1)
	p.pfProbeExpected.Store(probeID)
	p.pfProbeCh.Store(&probeCh)
	defer func() {
		p.pfProbeExpected.Store("")
		p.pfProbeCh.Store((*chan struct{})(nil))
	}()

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
func (p *prog) forceReloadPFMainRuleset() {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	// Dump running rules.
	natOut, err := exec.Command("pfctl", "-sn").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: force reload — failed to dump NAT rules")
		return
	}

	filterOut, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: force reload — failed to dump filter rules")
		return
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

	// Clean pf options (remove "set skip on lo0" if present).
	cleanedOptions, _ := pfGetCleanedOptions()

	// Reassemble in pf's required order: options → scrub → translation → filtering.
	var combined strings.Builder
	if cleanedOptions != "" {
		combined.WriteString(cleanedOptions)
	}
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
		return
	}

	// Also reload the anchor rules to ensure they're fresh.
	var vpnExemptions []vpnDNSExemption
	if p.vpnDNS != nil {
		vpnExemptions = p.vpnDNS.CurrentExemptions()
	}
	rulesStr := p.buildPFAnchorRules(vpnExemptions)
	if err := os.WriteFile(pfAnchorFile, []byte(rulesStr), 0644); err != nil {
		mainLog.Load().Error().Err(err).Msg("DNS intercept: force reload — failed to write anchor file")
	} else if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", pfAnchorFile).CombinedOutput(); err != nil {
		mainLog.Load().Error().Err(err).Msgf("DNS intercept: force reload — failed to load anchor (output: %s)", strings.TrimSpace(string(out)))
	}

	// Reset upstream transports — pf reload flushes state table, killing DoH connections.
	p.resetUpstreamTransports()

	mainLog.Load().Info().Msg("DNS intercept: force reload — pf ruleset and anchor reloaded successfully")
}

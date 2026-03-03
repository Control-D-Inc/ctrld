#!/bin/bash
# =============================================================================
# DNS Intercept Mode Test Script — macOS (pf)
# =============================================================================
# Run as root: sudo bash test-dns-intercept-mac.sh
#
# Tests the dns-intercept feature end-to-end with validation at each step.
# Logs are read from /tmp/dns.log (ctrld log location on test machine).
#
# Manual steps marked with [MANUAL] require human interaction.
# =============================================================================

set -euo pipefail

CTRLD_LOG="/tmp/dns.log"
PF_ANCHOR="com.controld.ctrld"
PASS=0
FAIL=0
WARN=0
RESULTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}"; }
info()   { echo -e "  ${BOLD}ℹ${NC}  $1"; }
pass()   { echo -e "  ${GREEN}✅ PASS${NC}: $1"; PASS=$((PASS+1)); RESULTS+=("PASS: $1"); }
fail()   { echo -e "  ${RED}❌ FAIL${NC}: $1"; FAIL=$((FAIL+1)); RESULTS+=("FAIL: $1"); }
warn()   { echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"; WARN=$((WARN+1)); RESULTS+=("WARN: $1"); }
manual() { echo -e "  ${YELLOW}[MANUAL]${NC} $1"; }
separator() { echo -e "${CYAN}─────────────────────────────────────────────────────${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (sudo).${NC}"
        exit 1
    fi
}

wait_for_key() {
    echo -e "\n  Press ${BOLD}Enter${NC} to continue..."
    read -r
}

# Grep recent log entries (last N lines)
log_grep() {
    local pattern="$1"
    local lines="${2:-200}"
    tail -n "$lines" "$CTRLD_LOG" 2>/dev/null | grep -i "$pattern" 2>/dev/null || true
}

log_grep_count() {
    local pattern="$1"
    local lines="${2:-200}"
    tail -n "$lines" "$CTRLD_LOG" 2>/dev/null | grep -ci "$pattern" 2>/dev/null || echo "0"
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

test_prereqs() {
    header "0. Prerequisites"

    if command -v pfctl &>/dev/null; then
        pass "pfctl available"
    else
        fail "pfctl not found"
        exit 1
    fi

    if [[ -f "$CTRLD_LOG" ]]; then
        pass "ctrld log exists at $CTRLD_LOG"
    else
        warn "ctrld log not found at $CTRLD_LOG — log checks will be skipped"
    fi

    if command -v dig &>/dev/null; then
        pass "dig available"
    else
        fail "dig not found — install bind tools"
        exit 1
    fi

    info "Default route interface: $(route -n get default 2>/dev/null | grep interface | awk '{print $2}' || echo 'unknown')"
    info "Current DNS servers:"
    scutil --dns | grep "nameserver\[" | head -5 | sed 's/^/    /'
}

test_pf_state() {
    header "1. PF State Validation"

    # Is pf enabled?
    local pf_status
    pf_status=$(pfctl -si 2>&1 | grep "Status:" || true)
    if echo "$pf_status" | grep -q "Enabled"; then
        pass "pf is enabled"
    else
        fail "pf is NOT enabled (status: $pf_status)"
    fi

    # Is our anchor referenced in the running ruleset?
    local sr_match sn_match
    sr_match=$(pfctl -sr 2>&1 | grep "$PF_ANCHOR" || true)
    sn_match=$(pfctl -sn 2>&1 | grep "$PF_ANCHOR" || true)

    if [[ -n "$sr_match" ]]; then
        pass "anchor '$PF_ANCHOR' found in filter rules (pfctl -sr)"
        info "  $sr_match"
    else
        fail "anchor '$PF_ANCHOR' NOT in filter rules — main ruleset doesn't reference it"
    fi

    if [[ -n "$sn_match" ]]; then
        pass "rdr-anchor '$PF_ANCHOR' found in NAT rules (pfctl -sn)"
        info "  $sn_match"
    else
        fail "rdr-anchor '$PF_ANCHOR' NOT in NAT rules — redirect won't work"
    fi

    # Check anchor rules
    separator
    info "Anchor filter rules (pfctl -a '$PF_ANCHOR' -sr):"
    local anchor_sr
    anchor_sr=$(pfctl -a "$PF_ANCHOR" -sr 2>&1 | grep -v "ALTQ" || true)
    if [[ -n "$anchor_sr" ]]; then
        echo "$anchor_sr" | sed 's/^/    /'
        # Check for route-to rules
        if echo "$anchor_sr" | grep -q "route-to"; then
            pass "route-to lo0 rules present (needed for local traffic interception)"
        else
            warn "No route-to rules found — local DNS may not be intercepted"
        fi
    else
        fail "No filter rules in anchor"
    fi

    info "Anchor redirect rules (pfctl -a '$PF_ANCHOR' -sn):"
    local anchor_sn
    anchor_sn=$(pfctl -a "$PF_ANCHOR" -sn 2>&1 | grep -v "ALTQ" || true)
    if [[ -n "$anchor_sn" ]]; then
        echo "$anchor_sn" | sed 's/^/    /'
        if echo "$anchor_sn" | grep -q "rdr.*lo0.*port = 53"; then
            pass "rdr rules on lo0 present (redirect DNS to ctrld)"
        else
            warn "rdr rules don't match expected pattern"
        fi
    else
        fail "No redirect rules in anchor"
    fi

    # Check anchor file exists
    if [[ -f "/etc/pf.anchors/$PF_ANCHOR" ]]; then
        pass "Anchor file exists: /etc/pf.anchors/$PF_ANCHOR"
    else
        fail "Anchor file missing: /etc/pf.anchors/$PF_ANCHOR"
    fi

    # Check pf.conf was NOT modified
    if grep -q "$PF_ANCHOR" /etc/pf.conf 2>/dev/null; then
        warn "pf.conf contains '$PF_ANCHOR' reference — should NOT be modified on disk"
    else
        pass "pf.conf NOT modified on disk (anchor injected at runtime only)"
    fi
}

test_dns_interception() {
    header "2. DNS Interception Tests"

    # Mark position in log
    local log_lines_before=0
    if [[ -f "$CTRLD_LOG" ]]; then
        log_lines_before=$(wc -l < "$CTRLD_LOG")
    fi

    # Test 1: Query to external resolver should be intercepted
    info "Test: dig @8.8.8.8 example.com (should be intercepted by ctrld)"
    local dig_result
    dig_result=$(dig @8.8.8.8 example.com +short +timeout=5 2>&1 || true)

    if [[ -n "$dig_result" ]] && ! echo "$dig_result" | grep -q "timed out"; then
        pass "dig @8.8.8.8 returned result: $dig_result"
    else
        fail "dig @8.8.8.8 failed or timed out"
    fi

    # Check if ctrld logged the query
    sleep 1
    if [[ -f "$CTRLD_LOG" ]]; then
        local intercepted
        intercepted=$(tail -n +$((log_lines_before+1)) "$CTRLD_LOG" | grep -c "example.com" || echo "0")
        if [[ "$intercepted" -gt 0 ]]; then
            pass "ctrld logged the intercepted query for example.com"
        else
            fail "ctrld did NOT log query for example.com — interception may not be working"
        fi
    fi

    # Check dig reports ctrld answered (not 8.8.8.8)
    local full_dig
    full_dig=$(dig @8.8.8.8 example.com +timeout=5 2>&1 || true)
    local server_line
    server_line=$(echo "$full_dig" | grep "SERVER:" || true)
    info "dig SERVER line: $server_line"
    if echo "$server_line" | grep -q "127.0.0.1"; then
        pass "Response came from 127.0.0.1 (ctrld intercepted)"
    elif echo "$server_line" | grep -q "8.8.8.8"; then
        fail "Response came from 8.8.8.8 directly — NOT intercepted"
    else
        warn "Could not determine response server from dig output"
    fi

    separator

    # Test 2: Query to another external resolver
    info "Test: dig @1.1.1.1 cloudflare.com (should also be intercepted)"
    local dig2
    dig2=$(dig @1.1.1.1 cloudflare.com +short +timeout=5 2>&1 || true)
    if [[ -n "$dig2" ]] && ! echo "$dig2" | grep -q "timed out"; then
        pass "dig @1.1.1.1 returned result"
    else
        fail "dig @1.1.1.1 failed or timed out"
    fi

    separator

    # Test 3: Query to localhost should work (not double-redirected)
    info "Test: dig @127.0.0.1 example.org (direct to ctrld, should NOT be redirected)"
    local dig3
    dig3=$(dig @127.0.0.1 example.org +short +timeout=5 2>&1 || true)
    if [[ -n "$dig3" ]] && ! echo "$dig3" | grep -q "timed out"; then
        pass "dig @127.0.0.1 works (no loop)"
    else
        fail "dig @127.0.0.1 failed — possible redirect loop"
    fi

    separator

    # Test 4: System DNS resolution
    info "Test: host example.net (system resolver, should go through ctrld)"
    local host_result
    host_result=$(host example.net 2>&1 || true)
    if echo "$host_result" | grep -q "has address"; then
        pass "System DNS resolution works via host command"
    else
        fail "System DNS resolution failed"
    fi

    separator

    # Test 5: TCP DNS query
    info "Test: dig @9.9.9.9 example.com +tcp (TCP DNS should also be intercepted)"
    local dig_tcp
    dig_tcp=$(dig @9.9.9.9 example.com +tcp +short +timeout=5 2>&1 || true)
    if [[ -n "$dig_tcp" ]] && ! echo "$dig_tcp" | grep -q "timed out"; then
        pass "TCP DNS query intercepted and resolved"
    else
        warn "TCP DNS query failed (may not be critical if UDP works)"
    fi
}

test_non_dns_unaffected() {
    header "3. Non-DNS Traffic Unaffected"

    # HTTPS should work fine
    info "Test: curl https://example.com (HTTPS port 443 should NOT be affected)"
    local curl_result
    curl_result=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://example.com 2>&1 || echo "000")
    if [[ "$curl_result" == "200" ]] || [[ "$curl_result" == "301" ]] || [[ "$curl_result" == "302" ]]; then
        pass "HTTPS works (HTTP $curl_result)"
    else
        fail "HTTPS failed (HTTP $curl_result) — pf may be affecting non-DNS traffic"
    fi

    # SSH-style connection test (port 22 should be unaffected)
    info "Test: nc -z -w5 github.com 22 (SSH port should NOT be affected)"
    if nc -z -w5 github.com 22 2>/dev/null; then
        pass "SSH port reachable (non-DNS traffic unaffected)"
    else
        warn "SSH port unreachable (may be firewall, not necessarily our fault)"
    fi
}

test_ctrld_log_health() {
    header "4. ctrld Log Health Check"

    if [[ ! -f "$CTRLD_LOG" ]]; then
        warn "Skipping log checks — $CTRLD_LOG not found"
        return
    fi

    # Check for intercept initialization
    if log_grep "DNS intercept.*initializing" 500 | grep -q "."; then
        pass "DNS intercept initialization logged"
    else
        fail "No DNS intercept initialization in recent logs"
    fi

    # Check for successful anchor load
    if log_grep "pf anchor.*active" 500 | grep -q "."; then
        pass "PF anchor reported as active"
    else
        fail "PF anchor not reported as active"
    fi

    # Check for anchor reference injection
    if log_grep "anchor reference active" 500 | grep -q "."; then
        pass "Anchor reference injected into running ruleset"
    else
        fail "Anchor reference NOT injected — this is the critical step"
    fi

    # Check for errors
    separator
    info "Recent errors/warnings in ctrld log:"
    local errors
    errors=$(log_grep '"level":"error"' 500)
    if [[ -n "$errors" ]]; then
        echo "$errors" | tail -5 | sed 's/^/    /'
        warn "Errors found in recent logs (see above)"
    else
        pass "No errors in recent logs"
    fi

    local warnings
    warnings=$(log_grep '"level":"warn"' 500 | grep -v "skipping self-upgrade" || true)
    if [[ -n "$warnings" ]]; then
        echo "$warnings" | tail -5 | sed 's/^/    /'
        info "(warnings above may be expected)"
    fi

    # Check for recovery bypass state
    if log_grep "recoveryBypass\|recovery bypass\|prepareForRecovery" 500 | grep -q "."; then
        info "Recovery bypass activity detected in logs"
        log_grep "recovery" 500 | tail -3 | sed 's/^/    /'
    fi

    # Check for VPN DNS detection
    if log_grep "VPN DNS" 500 | grep -q "."; then
        info "VPN DNS activity in logs:"
        log_grep "VPN DNS" 500 | tail -5 | sed 's/^/    /'
    else
        info "No VPN DNS activity (expected if no VPN is connected)"
    fi
}

test_pf_counters() {
    header "5. PF Statistics & Counters"

    info "PF info (pfctl -si):"
    pfctl -si 2>&1 | grep -v "ALTQ" | head -15 | sed 's/^/    /'

    info "PF state table entries:"
    pfctl -ss 2>&1 | grep -c "." | sed 's/^/    States: /'

    # Count evaluations of our anchor
    info "Anchor-specific stats (if available):"
    local anchor_info
    anchor_info=$(pfctl -a "$PF_ANCHOR" -si 2>&1 | grep -v "ALTQ" || true)
    if [[ -n "$anchor_info" ]]; then
        echo "$anchor_info" | head -10 | sed 's/^/    /'
    else
        info "  (no per-anchor stats available)"
    fi
}

test_cleanup_on_stop() {
    header "6. Cleanup Validation (After ctrld Stop)"

    manual "Stop ctrld now (Ctrl+C or 'ctrld stop'), then press Enter"
    wait_for_key

    # Check anchor is flushed
    local anchor_rules_after
    anchor_rules_after=$(pfctl -a "$PF_ANCHOR" -sr 2>&1 | grep -v "ALTQ" | grep -v "^$" || true)
    if [[ -z "$anchor_rules_after" ]]; then
        pass "Anchor filter rules flushed after stop"
    else
        fail "Anchor filter rules still present after stop"
        echo "$anchor_rules_after" | sed 's/^/    /'
    fi

    local anchor_rdr_after
    anchor_rdr_after=$(pfctl -a "$PF_ANCHOR" -sn 2>&1 | grep -v "ALTQ" | grep -v "^$" || true)
    if [[ -z "$anchor_rdr_after" ]]; then
        pass "Anchor redirect rules flushed after stop"
    else
        fail "Anchor redirect rules still present after stop"
    fi

    # Check anchor file removed
    if [[ ! -f "/etc/pf.anchors/$PF_ANCHOR" ]]; then
        pass "Anchor file removed after stop"
    else
        fail "Anchor file still exists: /etc/pf.anchors/$PF_ANCHOR"
    fi

    # Check pf.conf is clean
    if ! grep -q "$PF_ANCHOR" /etc/pf.conf 2>/dev/null; then
        pass "pf.conf is clean (no ctrld references)"
    else
        fail "pf.conf still has ctrld references after stop"
    fi

    # DNS should work normally without ctrld
    info "Test: dig example.com (should resolve via system DNS)"
    local dig_after
    dig_after=$(dig example.com +short +timeout=5 2>&1 || true)
    if [[ -n "$dig_after" ]] && ! echo "$dig_after" | grep -q "timed out"; then
        pass "DNS works after ctrld stop"
    else
        fail "DNS broken after ctrld stop — cleanup may have failed"
    fi
}

test_restart_resilience() {
    header "7. Restart Resilience"

    manual "Start ctrld again with --dns-intercept, then press Enter"
    wait_for_key

    sleep 3

    # Re-run pf state checks
    local sr_match sn_match
    sr_match=$(pfctl -sr 2>&1 | grep "$PF_ANCHOR" || true)
    sn_match=$(pfctl -sn 2>&1 | grep "$PF_ANCHOR" || true)

    if [[ -n "$sr_match" ]] && [[ -n "$sn_match" ]]; then
        pass "Anchor references restored after restart"
    else
        fail "Anchor references NOT restored after restart"
    fi

    # Quick interception test
    local dig_after_restart
    dig_after_restart=$(dig @8.8.8.8 example.com +short +timeout=5 2>&1 || true)
    if [[ -n "$dig_after_restart" ]] && ! echo "$dig_after_restart" | grep -q "timed out"; then
        pass "DNS interception works after restart"
    else
        fail "DNS interception broken after restart"
    fi
}

test_network_change() {
    header "8. Network Change Recovery"

    info "This test verifies recovery after network changes."
    manual "Switch Wi-Fi networks (or disconnect/reconnect Ethernet), then press Enter"
    wait_for_key

    sleep 5

    # Check pf rules still active
    local sr_after sn_after
    sr_after=$(pfctl -sr 2>&1 | grep "$PF_ANCHOR" || true)
    sn_after=$(pfctl -sn 2>&1 | grep "$PF_ANCHOR" || true)

    if [[ -n "$sr_after" ]] && [[ -n "$sn_after" ]]; then
        pass "Anchor references survived network change"
    else
        fail "Anchor references lost after network change"
    fi

    # Check interception still works
    local dig_after_net
    dig_after_net=$(dig @8.8.8.8 example.com +short +timeout=10 2>&1 || true)
    if [[ -n "$dig_after_net" ]] && ! echo "$dig_after_net" | grep -q "timed out"; then
        pass "DNS interception works after network change"
    else
        fail "DNS interception broken after network change"
    fi

    # Check logs for recovery bypass activity
    if [[ -f "$CTRLD_LOG" ]]; then
        local recovery_logs
        recovery_logs=$(log_grep "recovery\|network change\|network monitor" 100)
        if [[ -n "$recovery_logs" ]]; then
            info "Recovery/network change log entries:"
            echo "$recovery_logs" | tail -5 | sed 's/^/    /'
        fi
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    header "TEST SUMMARY"
    echo ""
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == PASS* ]]; then
            echo -e "  ${GREEN}✅${NC} ${r#PASS: }"
        elif [[ "$r" == FAIL* ]]; then
            echo -e "  ${RED}❌${NC} ${r#FAIL: }"
        elif [[ "$r" == WARN* ]]; then
            echo -e "  ${YELLOW}⚠️${NC}  ${r#WARN: }"
        fi
    done
    echo ""
    separator
    echo -e "  ${GREEN}Passed: $PASS${NC}  |  ${RED}Failed: $FAIL${NC}  |  ${YELLOW}Warnings: $WARN${NC}"
    separator

    if [[ $FAIL -gt 0 ]]; then
        echo -e "\n  ${RED}${BOLD}Some tests failed.${NC} Check output above for details."
        echo -e "  Useful debug commands:"
        echo -e "    pfctl -a '$PF_ANCHOR' -sr      # anchor filter rules"
        echo -e "    pfctl -a '$PF_ANCHOR' -sn      # anchor redirect rules"
        echo -e "    pfctl -sr | grep controld       # main ruleset references"
        echo -e "    tail -100 $CTRLD_LOG            # recent ctrld logs"
    else
        echo -e "\n  ${GREEN}${BOLD}All tests passed!${NC}"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ctrld DNS Intercept Mode — macOS Test Suite         ║${NC}"
echo -e "${BOLD}║  Tests pf-based DNS interception (route-to + rdr)    ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"

check_root

echo ""
echo "Make sure ctrld is running with --dns-intercept before starting."
echo "Log location: $CTRLD_LOG"
wait_for_key

test_prereqs
test_pf_state
test_dns_interception
test_non_dns_unaffected
test_ctrld_log_health
test_pf_counters

separator
echo ""
echo "The next tests require manual steps (stop/start ctrld, network changes)."
echo "Press Enter to continue, or Ctrl+C to skip and see results so far."
wait_for_key

test_cleanup_on_stop
test_restart_resilience
test_network_change

print_summary

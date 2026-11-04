#!/bin/bash
# test-recovery-bypass.sh — Test DNS intercept recovery bypass (captive portal simulation)
#
# Simulates a captive portal by:
#   1. Discovering ctrld's upstream IPs from active connections
#   2. Blackholing ALL of them via route table
#   3. Cycling wifi to trigger network change → recovery flow
#   4. Verifying recovery bypass forwards to OS/DHCP resolver
#   5. Unblocking and verifying normal operation resumes
#
# SAFE: Uses route add/delete + networksetup — cleaned up on exit (including Ctrl+C).
#
# Usage: sudo bash test-recovery-bypass.sh [wifi_interface]
#   wifi_interface defaults to en0
#
# Prerequisites:
#   - ctrld running with --dns-intercept and -v 1 --log /tmp/dns.log
#   - Run as root (sudo)

set -euo pipefail

WIFI_IFACE="${1:-en0}"
CTRLD_LOG="/tmp/dns.log"
BLOCKED_IPS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ── Safety: always clean up on exit ──────────────────────────────────────────
cleanup() {
    echo ""
    log "═══ CLEANUP ═══"

    # Ensure wifi is on
    log "Ensuring wifi is on..."
    networksetup -setairportpower "$WIFI_IFACE" on 2>/dev/null || true

    # Remove all blackhole routes
    for ip in "${BLOCKED_IPS[@]}"; do
        route delete -host "$ip" 2>/dev/null && log "Removed route for $ip" || true
    done

    log "Cleanup complete. Internet should be restored."
    log "(If not, run: sudo networksetup -setairportpower $WIFI_IFACE on)"
}
trap cleanup EXIT INT TERM

# ── Pre-checks ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0 $*"
    exit 1
fi

if [[ ! -f "$CTRLD_LOG" ]]; then
    fail "ctrld log not found at $CTRLD_LOG"
    echo "Start ctrld with: ctrld run --dns-intercept --cd <uid> -v 1 --log $CTRLD_LOG"
    exit 1
fi

# Check wifi interface exists
if ! networksetup -getairportpower "$WIFI_IFACE" >/dev/null 2>&1; then
    fail "Wifi interface $WIFI_IFACE not found"
    echo "Try: networksetup -listallhardwareports"
    exit 1
fi

log "═══════════════════════════════════════════════════════════"
log "  Recovery Bypass Test (Captive Portal Simulation)"
log "═══════════════════════════════════════════════════════════"
log "Wifi interface: $WIFI_IFACE"
log "ctrld log:      $CTRLD_LOG"
echo ""

# ── Phase 1: Discover upstream IPs ──────────────────────────────────────────
log "Phase 1: Discovering ctrld upstream IPs from active connections"

# Find ctrld's established connections (DoH uses port 443)
CTRLD_CONNS=$(lsof -i -n -P 2>/dev/null | grep -i ctrld | grep ESTABLISHED || true)
if [[ -z "$CTRLD_CONNS" ]]; then
    warn "No established ctrld connections found via lsof"
    warn "Trying: ss/netstat fallback..."
    CTRLD_CONNS=$(netstat -an 2>/dev/null | grep "\.443 " | grep ESTABLISHED || true)
fi

echo "$CTRLD_CONNS" | head -10 | while read -r line; do
    log "  $line"
done

# Extract unique remote IPs from ctrld connections
UPSTREAM_IPS=()
while IFS= read -r ip; do
    [[ -n "$ip" ]] && UPSTREAM_IPS+=("$ip")
done < <(echo "$CTRLD_CONNS" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | while read -r ip; do
    # Filter out local/private IPs — we only want the upstream DoH server IPs
    if [[ ! "$ip" =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
        echo "$ip"
    fi
done)

# Also try to resolve known Control D DoH endpoints
for host in dns.controld.com freedns.controld.com; do
    for ip in $(dig +short "$host" 2>/dev/null || true); do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            UPSTREAM_IPS+=("$ip")
        fi
    done
done

# Deduplicate
UPSTREAM_IPS=($(printf '%s\n' "${UPSTREAM_IPS[@]}" | sort -u))

if [[ ${#UPSTREAM_IPS[@]} -eq 0 ]]; then
    fail "Could not discover any upstream IPs!"
    echo "Check: lsof -i -n -P | grep ctrld"
    exit 1
fi

log "Found ${#UPSTREAM_IPS[@]} upstream IP(s):"
for ip in "${UPSTREAM_IPS[@]}"; do
    log "  $ip"
done
echo ""

# ── Phase 2: Baseline check ─────────────────────────────────────────────────
log "Phase 2: Baseline — verify DNS works normally"
BASELINE=$(dig +short +timeout=5 example.com @127.0.0.1 2>/dev/null || true)
if [[ -z "$BASELINE" ]]; then
    fail "DNS not working before test!"
    exit 1
fi
pass "Baseline: example.com → $BASELINE"

LOG_LINES_BEFORE=$(wc -l < "$CTRLD_LOG" | tr -d ' ')
log "Log position: line $LOG_LINES_BEFORE"
echo ""

# ── Phase 3: Block all upstream IPs ─────────────────────────────────────────
log "Phase 3: Blackholing all upstream IPs"
for ip in "${UPSTREAM_IPS[@]}"; do
    route delete -host "$ip" 2>/dev/null || true  # clean slate
    route add -host "$ip" 127.0.0.1 2>/dev/null
    BLOCKED_IPS+=("$ip")
    log "  Blocked: $ip → 127.0.0.1"
done
pass "All ${#UPSTREAM_IPS[@]} upstream IPs blackholed"
echo ""

# ── Phase 4: Cycle wifi to trigger network change ───────────────────────────
log "Phase 4: Cycling wifi to trigger network change event"
log "  Turning wifi OFF..."
networksetup -setairportpower "$WIFI_IFACE" off
sleep 3

log "  Turning wifi ON..."
networksetup -setairportpower "$WIFI_IFACE" on

log "  Waiting for wifi to reconnect (up to 15s)..."
WIFI_UP=false
for i in $(seq 1 15); do
    # Check if we have an IP on the wifi interface
    IF_IP=$(ipconfig getifaddr "$WIFI_IFACE" 2>/dev/null || true)
    if [[ -n "$IF_IP" ]]; then
        WIFI_UP=true
        pass "Wifi reconnected: $WIFI_IFACE → $IF_IP"
        break
    fi
    sleep 1
done

if [[ "$WIFI_UP" == "false" ]]; then
    fail "Wifi did not reconnect in 15s!"
    warn "Cleaning up and exiting..."
    exit 1
fi

log "  Waiting 5s for ctrld network monitor to fire..."
sleep 5
echo ""

# ── Phase 5: Query and watch for recovery ────────────────────────────────────
log "Phase 5: Sending queries — upstream is blocked, recovery should activate"
log "  (ctrld should detect upstream failure → enable recovery bypass → use DHCP DNS)"
echo ""

RECOVERY_DETECTED=false
BYPASS_ACTIVE=false
DNS_DURING_BYPASS=false
QUERY_COUNT=0

for i in $(seq 1 30); do
    QUERY_COUNT=$((QUERY_COUNT + 1))
    RESULT=$(dig +short +timeout=3 "example.com" @127.0.0.1 2>/dev/null || true)

    if [[ -n "$RESULT" ]]; then
        log "  Query #$QUERY_COUNT: example.com → $RESULT ✓"
    else
        log "  Query #$QUERY_COUNT: example.com → FAIL ✗"
    fi

    # Check logs
    NEW_LOGS=$(tail -n +$((LOG_LINES_BEFORE + 1)) "$CTRLD_LOG" 2>/dev/null || true)

    if [[ "$RECOVERY_DETECTED" == "false" ]] && echo "$NEW_LOGS" | grep -qiE "enabling DHCP bypass|triggering recovery|No healthy"; then
        echo ""
        pass "🎯 Recovery flow triggered!"
        RECOVERY_DETECTED=true
        echo "$NEW_LOGS" | grep -iE "recovery|bypass|DHCP|No healthy|network change" | tail -8 | while read -r line; do
            echo "  📋 $line"
        done
        echo ""
    fi

    if [[ "$BYPASS_ACTIVE" == "false" ]] && echo "$NEW_LOGS" | grep -qi "Recovery bypass active"; then
        pass "🔄 Recovery bypass is forwarding queries to OS/DHCP resolver"
        BYPASS_ACTIVE=true
    fi

    if [[ "$RECOVERY_DETECTED" == "true" && -n "$RESULT" ]]; then
        pass "✅ DNS resolves during recovery bypass: example.com → $RESULT"
        DNS_DURING_BYPASS=true
        break
    fi

    sleep 2
done

# ── Phase 6: Show all recovery-related log entries ──────────────────────────
echo ""
log "Phase 6: All recovery-related ctrld log entries"
log "────────────────────────────────────────────────"
NEW_LOGS=$(tail -n +$((LOG_LINES_BEFORE + 1)) "$CTRLD_LOG" 2>/dev/null || true)
RELEVANT=$(echo "$NEW_LOGS" | grep -iE "recovery|bypass|DHCP|unhealthy|upstream.*fail|No healthy|network change|network monitor|OS resolver" || true)
if [[ -n "$RELEVANT" ]]; then
    echo "$RELEVANT" | head -40 | while read -r line; do
        echo "  $line"
    done
else
    warn "No recovery-related log entries found!"
    log "Last 15 lines of ctrld log:"
    tail -15 "$CTRLD_LOG" | while read -r line; do
        echo "  $line"
    done
fi

# ── Phase 7: Unblock and verify full recovery ───────────────────────────────
echo ""
log "Phase 7: Unblocking upstream IPs"
for ip in "${BLOCKED_IPS[@]}"; do
    route delete -host "$ip" 2>/dev/null && log "  Unblocked: $ip" || true
done
BLOCKED_IPS=()  # clear so cleanup doesn't double-delete
pass "All upstream IPs unblocked"

log "Waiting for ctrld to recover (up to 30s)..."
LOG_LINES_UNBLOCK=$(wc -l < "$CTRLD_LOG" | tr -d ' ')
RECOVERY_COMPLETE=false

for i in $(seq 1 15); do
    dig +short +timeout=3 example.com @127.0.0.1 >/dev/null 2>&1 || true
    POST_LOGS=$(tail -n +$((LOG_LINES_UNBLOCK + 1)) "$CTRLD_LOG" 2>/dev/null || true)

    if echo "$POST_LOGS" | grep -qiE "recovery complete|disabling DHCP bypass|Upstream.*recovered"; then
        RECOVERY_COMPLETE=true
        pass "ctrld recovered — normal operation resumed"
        echo "$POST_LOGS" | grep -iE "recovery|recovered|bypass|disabling" | head -5 | while read -r line; do
            echo "  📋 $line"
        done
        break
    fi
    sleep 2
done

[[ "$RECOVERY_COMPLETE" == "false" ]] && warn "Recovery completion not detected (may need more time)"

# Final check
echo ""
log "Phase 8: Final DNS verification"
sleep 2
FINAL=$(dig +short +timeout=5 example.com @127.0.0.1 2>/dev/null || true)
if [[ -n "$FINAL" ]]; then
    pass "DNS working: example.com → $FINAL"
else
    fail "DNS not resolving"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════════"
log "  Test Summary"
log "═══════════════════════════════════════════════════════════"
[[ "$RECOVERY_DETECTED" == "true" ]]  && pass "Recovery bypass activated" || fail "Recovery bypass NOT activated"
[[ "$BYPASS_ACTIVE" == "true" ]]      && pass "Queries forwarded to OS/DHCP resolver" || warn "OS resolver forwarding not confirmed"
[[ "$DNS_DURING_BYPASS" == "true" ]]  && pass "DNS resolved during bypass (proof of OS resolver leak)" || warn "DNS during bypass not confirmed"
[[ "$RECOVERY_COMPLETE" == "true" ]]  && pass "Normal operation resumed after unblock" || warn "Recovery completion not confirmed"
[[ -n "${FINAL:-}" ]]                && pass "DNS functional at end of test" || fail "DNS broken at end of test"
echo ""
log "Full log since test: tail -n +$LOG_LINES_BEFORE $CTRLD_LOG"
log "Recovery entries:    tail -n +$LOG_LINES_BEFORE $CTRLD_LOG | grep -i recovery"

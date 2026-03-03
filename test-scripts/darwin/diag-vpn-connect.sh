#!/bin/bash
# diag-vpn-connect.sh — Diagnostic script for testing ctrld dns-intercept
# during VPN VPN connection on macOS.
#
# Usage: sudo ./diag-vpn-connect.sh
#
# Run this BEFORE connecting VPN. It polls every 0.5s and captures:
#   1. pf anchor state (are ctrld anchors present?)
#   2. pf state table entries (rdr interception working?)
#   3. ctrld log events (watchdog, rebootstrap, errors)
#   4. scutil DNS resolver state
#   5. Active tunnel interfaces
#   6. dig test query results
#
# Output goes to /tmp/diag-vpn-<timestamp>/
# Press Ctrl-C to stop. A summary is printed at the end.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

CTRLD_LOG="${CTRLD_LOG:-/tmp/dns.log}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="/tmp/diag-vpn-${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo "=== VPN + ctrld DNS Intercept Diagnostic ==="
echo "Output: $OUTDIR"
echo "ctrld log: $CTRLD_LOG"
echo ""
echo "1. Start this script"
echo "2. Connect VPN"
echo "3. Wait ~30 seconds"
echo "4. Try: dig popads.net / dig @127.0.0.1 popads.net"
echo "5. Ctrl-C to stop and see summary"
echo ""
echo "Polling every 0.5s... Press Ctrl-C to stop."
echo ""

# Track ctrld log position
if [ -f "$CTRLD_LOG" ]; then
    LOG_START_LINE=$(wc -l < "$CTRLD_LOG")
else
    LOG_START_LINE=0
fi

ITER=0
DIG_FAIL=0
DIG_OK=0
ANCHOR_MISSING=0
ANCHOR_PRESENT=0
PF_WIPE_COUNT=0
FORCE_REBOOT_COUNT=0
LAST_TUNNEL_IFACES=""

cleanup() {
    echo ""
    echo "=== Stopping diagnostic ==="

    # Capture final state
    echo "--- Final pf state ---" > "$OUTDIR/final-pfctl.txt"
    pfctl -sa 2>/dev/null >> "$OUTDIR/final-pfctl.txt" 2>&1 || true

    echo "--- Final scutil ---" > "$OUTDIR/final-scutil.txt"
    scutil --dns >> "$OUTDIR/final-scutil.txt" 2>&1 || true

    # Extract ctrld log events since start
    if [ -f "$CTRLD_LOG" ]; then
        tail -n +$((LOG_START_LINE + 1)) "$CTRLD_LOG" > "$OUTDIR/ctrld-events.log" 2>/dev/null || true

        # Extract key events
        echo "--- Watchdog events ---" > "$OUTDIR/summary-watchdog.txt"
        grep -i "watchdog\|anchor.*missing\|anchor.*restored\|force-reset\|re-bootstrapping\|force re-bootstrapping" "$OUTDIR/ctrld-events.log" >> "$OUTDIR/summary-watchdog.txt" 2>/dev/null || true

        echo "--- Errors ---" > "$OUTDIR/summary-errors.txt"
        grep '"level":"error"' "$OUTDIR/ctrld-events.log" >> "$OUTDIR/summary-errors.txt" 2>/dev/null || true

        echo "--- Network changes ---" > "$OUTDIR/summary-network.txt"
        grep -i "Network change\|tunnel interface\|Ignoring interface" "$OUTDIR/ctrld-events.log" >> "$OUTDIR/summary-network.txt" 2>/dev/null || true

        echo "--- Transport resets ---" > "$OUTDIR/summary-transport.txt"
        grep -i "re-bootstrap\|force.*bootstrap\|dialing to\|connected to" "$OUTDIR/ctrld-events.log" >> "$OUTDIR/summary-transport.txt" 2>/dev/null || true

        # Count key events
        PF_WIPE_COUNT=$(grep -c "anchor.*missing\|restoring pf" "$OUTDIR/ctrld-events.log" 2>/dev/null || echo 0)
        FORCE_REBOOT_COUNT=$(grep -c "force re-bootstrapping\|force-reset" "$OUTDIR/ctrld-events.log" 2>/dev/null || echo 0)
        DEADLINE_COUNT=$(grep -c "context deadline exceeded" "$OUTDIR/ctrld-events.log" 2>/dev/null || echo 0)
        FALLBACK_COUNT=$(grep -c "OS resolver retry query successful" "$OUTDIR/ctrld-events.log" 2>/dev/null || echo 0)
    fi

    echo ""
    echo "========================================="
    echo "         DIAGNOSTIC SUMMARY"
    echo "========================================="
    echo "Duration: $ITER iterations (~$((ITER / 2))s)"
    echo ""
    echo "pf Anchor Status:"
    echo "  Present: $ANCHOR_PRESENT times"
    echo "  Missing: $ANCHOR_MISSING times"
    echo ""
    echo "dig Tests (popads.net):"
    echo "  Success: $DIG_OK"
    echo "  Failed:  $DIG_FAIL"
    echo ""
    echo "ctrld Log Events:"
    echo "  pf wipes detected:      $PF_WIPE_COUNT"
    echo "  Force rebootstraps:     $FORCE_REBOOT_COUNT"
    echo "  Context deadline errors: ${DEADLINE_COUNT:-0}"
    echo "  OS resolver fallbacks:   ${FALLBACK_COUNT:-0}"
    echo ""
    echo "Last tunnel interfaces: ${LAST_TUNNEL_IFACES:-none}"
    echo ""
    echo "Files saved to: $OUTDIR/"
    echo "  final-pfctl.txt        — full pfctl -sa at exit"
    echo "  final-scutil.txt       — scutil --dns at exit"
    echo "  ctrld-events.log       — ctrld log during test"
    echo "  summary-watchdog.txt   — watchdog events"
    echo "  summary-errors.txt     — errors"
    echo "  summary-transport.txt  — transport reset events"
    echo "  timeline.log           — per-iteration state"
    echo "========================================="
    exit 0
}

trap cleanup INT TERM

while true; do
    ITER=$((ITER + 1))
    NOW=$(date '+%H:%M:%S.%3N' 2>/dev/null || date '+%H:%M:%S')

    # 1. Check pf anchor presence
    ANCHOR_STATUS="MISSING"
    if pfctl -sr 2>/dev/null | grep -q "com.controld.ctrld"; then
        ANCHOR_STATUS="PRESENT"
        ANCHOR_PRESENT=$((ANCHOR_PRESENT + 1))
    else
        ANCHOR_MISSING=$((ANCHOR_MISSING + 1))
    fi

    # 2. Check tunnel interfaces
    TUNNEL_IFACES=$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -E '^(utun|ipsec|ppp|tap|tun)' | \
        while read iface; do
            # Only list interfaces that are UP and have an IP
            if ifconfig "$iface" 2>/dev/null | grep -q "inet "; then
                echo -n "$iface "
            fi
        done)
    TUNNEL_IFACES=$(echo "$TUNNEL_IFACES" | xargs)  # trim
    if [ -n "$TUNNEL_IFACES" ]; then
        LAST_TUNNEL_IFACES="$TUNNEL_IFACES"
    fi

    # 3. Count rdr states (three-part = intercepted)
    RDR_COUNT=$(pfctl -ss 2>/dev/null | grep -c "127.0.0.1:53 <-" || echo 0)

    # 4. Quick dig test (0.5s timeout)
    DIG_RESULT="SKIP"
    if [ $((ITER % 4)) -eq 0 ]; then  # every 2 seconds
        if dig +time=1 +tries=1 popads.net A @127.0.0.1 +short >/dev/null 2>&1; then
            DIG_RESULT="OK"
            DIG_OK=$((DIG_OK + 1))
        else
            DIG_RESULT="FAIL"
            DIG_FAIL=$((DIG_FAIL + 1))
        fi
    fi

    # 5. Check latest ctrld log for recent errors
    RECENT_ERR=""
    if [ -f "$CTRLD_LOG" ]; then
        RECENT_ERR=$(tail -5 "$CTRLD_LOG" 2>/dev/null | grep -o '"message":"[^"]*deadline[^"]*"' | tail -1 || true)
    fi

    # Output timeline
    LINE="[$NOW] anchor=$ANCHOR_STATUS rdr_states=$RDR_COUNT tunnels=[$TUNNEL_IFACES] dig=$DIG_RESULT $RECENT_ERR"
    echo "$LINE"
    echo "$LINE" >> "$OUTDIR/timeline.log"

    sleep 0.5
done

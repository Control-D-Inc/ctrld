#!/bin/bash
# diag-pf-poll.sh — Polls pf rules, options, states, and DNS every 2s
# Usage: sudo bash diag-pf-poll.sh | tee /tmp/pf-poll.log
# Steps: 1) Run script  2) Connect Windscribe  3) Start ctrld  4) Ctrl-C when done

set -u
LOG="/tmp/pf-poll-$(date +%s).log"
echo "=== PF Poll Diagnostic — logging to $LOG ==="
echo "Press Ctrl-C to stop"
echo ""

poll() {
    local ts=$(date '+%H:%M:%S.%3N')
    echo "======== [$ts] POLL ========"

    # 1. pf options — looking for "set skip on lo0"
    echo "--- pf options ---"
    pfctl -so 2>/dev/null | grep -i skip || echo "(no skip rules)"

    # 2. Main ruleset anchors — where is ctrld relative to block drop all?
    echo "--- main filter rules (summary) ---"
    pfctl -sr 2>/dev/null | head -30

    # 3. Main NAT/rdr rules
    echo "--- main nat/rdr rules (summary) ---"
    pfctl -sn 2>/dev/null | head -20

    # 4. ctrld anchor content
    echo "--- ctrld anchor (filter) ---"
    pfctl -a com.apple.internet-sharing/ctrld -sr 2>/dev/null || echo "(no anchor)"
    echo "--- ctrld anchor (nat/rdr) ---"
    pfctl -a com.apple.internet-sharing/ctrld -sn 2>/dev/null || echo "(no anchor)"

    # 5. State count for rdr target (10.255.255.3) and loopback
    echo "--- states summary ---"
    local total=$(pfctl -ss 2>/dev/null | wc -l | tr -d ' ')
    local rdr=$(pfctl -ss 2>/dev/null | grep -c '10\.255\.255\.3' || true)
    local lo0=$(pfctl -ss 2>/dev/null | grep -c 'lo0' || true)
    echo "total=$total rdr_target=$rdr lo0=$lo0"

    # 6. Quick DNS test (1s timeout)
    echo "--- DNS tests ---"
    local direct=$(dig +short +time=1 +tries=1 example.com @127.0.0.1 2>&1 | head -1)
    local system=$(dig +short +time=1 +tries=1 example.com 2>&1 | head -1)
    echo "direct @127.0.0.1: $direct"
    echo "system DNS:        $system"

    # 7. Windscribe tunnel interface
    echo "--- tunnel interfaces ---"
    ifconfig -l | tr ' ' '\n' | grep -E '^utun' | while read iface; do
        echo -n "$iface: "
        ifconfig "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo "no ip"
    done

    echo ""
}

# Main loop
while true; do
    poll 2>&1 | tee -a "$LOG"
    sleep 2
done

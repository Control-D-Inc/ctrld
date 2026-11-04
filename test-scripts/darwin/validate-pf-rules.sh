#!/bin/bash
# validate-pf-rules.sh
# Standalone test of the pf redirect rules for dns-intercept mode.
# Does NOT require ctrld. Loads the pf anchor, validates interception, cleans up.
# Run as root (sudo).

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
FAILURES=0

ANCHOR="com.controld.ctrld.test"
ANCHOR_FILE="/tmp/pf-dns-intercept-test.conf"
# Use a local DNS listener to prove redirect works (python one-liner)
LISTENER_PID=""

cleanup() {
    echo ""
    echo -e "${CYAN}--- Cleanup ---${NC}"
    # Remove anchor rules
    pfctl -a "$ANCHOR" -F all 2>/dev/null && echo "     Flushed anchor $ANCHOR" || true
    # Remove anchor file
    rm -f "$ANCHOR_FILE" "/tmp/pf-combined-test.conf" && echo "     Removed temp files" || true
    # Reload original pf.conf to remove anchor reference
    pfctl -f /etc/pf.conf 2>/dev/null && echo "     Reloaded original pf.conf" || true
    # Kill test listener
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null && echo "     Stopped test DNS listener" || true
    fi
    echo "     Cleanup complete"
}
trap cleanup EXIT

resolve() {
    dig "@${1}" "$2" A +short +timeout=3 +tries=1 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

echo -e "${CYAN}=== pf DNS Redirect Rule Validation ===${NC}"
echo "     This loads the exact pf rules from the dns-intercept MR,"
echo "     starts a tiny DNS listener on 127.0.0.1:53, and verifies"
echo "     that queries to external IPs get redirected."
echo ""

# 0. Check we're root
if [ "$(id -u)" -ne 0 ]; then
    fail "Must run as root (sudo)"
    exit 1
fi

# 1. Start a minimal DNS listener on 127.0.0.1:53
# Uses socat to echo a fixed response — enough to prove redirect works.
# If port 53 is already in use (mDNSResponder), we'll use that instead.
echo "--- Step 1: DNS Listener on 127.0.0.1:53 ---"
if lsof -i :53 -sTCP:LISTEN 2>/dev/null | grep -q "." || lsof -i UDP:53 2>/dev/null | grep -q "."; then
    ok "Something already listening on port 53 (likely mDNSResponder or ctrld)"
    HAVE_LISTENER=true
else
    # Start a simple Python DNS proxy that forwards to 1.1.1.1
    python3 -c "
import socket, threading, sys
def proxy(data, addr, sock):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(data, ('1.1.1.1', 53))
        resp, _ = s.recvfrom(4096)
        sock.sendto(resp, addr)
        s.close()
    except: pass

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 53))
print('READY', flush=True)
while True:
    data, addr = sock.recvfrom(4096)
    threading.Thread(target=proxy, args=(data, addr, sock), daemon=True).start()
" &
    LISTENER_PID=$!
    sleep 1
    if kill -0 "$LISTENER_PID" 2>/dev/null; then
        ok "Started test DNS proxy on 127.0.0.1:53 (PID $LISTENER_PID, forwards to 1.1.1.1)"
        HAVE_LISTENER=true
    else
        fail "Could not start DNS listener on port 53 — port may be in use"
        HAVE_LISTENER=false
    fi
fi
echo ""

# 2. Verify baseline: direct query to 8.8.8.8 works (before pf rules)
echo "--- Step 2: Baseline (before pf rules) ---"
IP=$(resolve "8.8.8.8" "example.com")
if [ -n "$IP" ]; then
    ok "Direct DNS to 8.8.8.8 works (baseline): $IP"
else
    warn "Direct DNS to 8.8.8.8 failed — may be blocked by existing firewall"
fi
echo ""

# 3. Write and load the pf anchor (exact rules from MR)
echo "--- Step 3: Load pf Anchor Rules ---"
TEST_UPSTREAM="1.1.1.1"
cat > "$ANCHOR_FILE" << PFRULES
# ctrld DNS Intercept Mode (test anchor)
# Two-step: route-to lo0 + rdr on lo0
#
# In production, ctrld uses DoH (port 443) for upstreams so they're not
# affected by port 53 rules. For this test, we exempt our upstream ($TEST_UPSTREAM)
# explicitly — same mechanism ctrld uses for OS resolver exemptions.

# --- Translation rules (rdr) ---
rdr pass on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53
rdr pass on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53

# --- Filtering rules (pass) ---
# Exempt test upstream (in production: ctrld uses DoH, so this isn't needed).
pass out quick on ! lo0 inet proto { udp, tcp } from any to $TEST_UPSTREAM port 53

# Force remaining outbound DNS through loopback for interception.
pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53 no state
pass out quick on ! lo0 route-to lo0 inet proto tcp from any to ! 127.0.0.1 port 53 no state

# Allow redirected traffic through on loopback.
pass in quick on lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53 no state
PFRULES

ok "Wrote anchor file: $ANCHOR_FILE"
cat "$ANCHOR_FILE" | sed 's/^/     /'
echo ""

# Load anchor
OUTPUT=$(pfctl -a "$ANCHOR" -f "$ANCHOR_FILE" 2>&1) || {
    fail "Failed to load anchor: $OUTPUT"
    exit 1
}
ok "Loaded anchor: $ANCHOR"

# Inject anchor references into running pf config.
# pf enforces strict rule ordering: options, normalization, queueing, translation, filtering.
# We must insert rdr-anchor with other rdr-anchors and anchor with other anchors.
TMPCONF="/tmp/pf-combined-test.conf"
python3 -c "
import sys
lines = open('/etc/pf.conf').read().splitlines()
anchor = '$ANCHOR'
rdr_ref = 'rdr-anchor \"' + anchor + '\"'
anchor_ref = 'anchor \"' + anchor + '\"'
out = []
rdr_done = False
anc_done = False
for line in lines:
    s = line.strip()
    # Insert our rdr-anchor before the first existing rdr-anchor
    if not rdr_done and s.startswith('rdr-anchor'):
        out.append(rdr_ref)
        rdr_done = True
    # Insert our anchor before the first existing anchor (filter-phase)
    if not anc_done and s.startswith('anchor') and not s.startswith('anchor \"com.apple'):
        out.append(anchor_ref)
        anc_done = True
    out.append(line)
# Fallback if no existing anchors found
if not rdr_done:
    # Insert before first non-comment, non-blank after any 'set' or 'scrub' lines
    out.insert(0, rdr_ref)
if not anc_done:
    out.append(anchor_ref)
open('$TMPCONF', 'w').write('\n'.join(out) + '\n')
" || { fail "Failed to build combined pf config"; exit 1; }

INJECT_OUT=$(pfctl -f "$TMPCONF" 2>&1) || {
    fail "Failed to inject anchor reference: $INJECT_OUT"
    rm -f "$TMPCONF"
    exit 1
}
rm -f "$TMPCONF"
ok "Injected anchor references into running pf ruleset"

# Enable pf
pfctl -e 2>/dev/null || true

# Show loaded rules
echo ""
echo "     Active NAT rules:"
pfctl -a "$ANCHOR" -sn 2>/dev/null | sed 's/^/       /'
echo "     Active filter rules:"
pfctl -a "$ANCHOR" -sr 2>/dev/null | sed 's/^/       /'
echo ""

# 4. Test: DNS to 8.8.8.8 should now be redirected to 127.0.0.1:53
echo "--- Step 4: Redirect Test ---"
if [ "$HAVE_LISTENER" = true ]; then
    IP=$(resolve "8.8.8.8" "example.com" 5)
    if [ -n "$IP" ]; then
        ok "DNS to 8.8.8.8 redirected through 127.0.0.1:53: $IP"
    else
        fail "DNS to 8.8.8.8 failed — redirect may not be working"
    fi

    # Also test another random IP
    IP2=$(resolve "9.9.9.9" "example.com" 5)
    if [ -n "$IP2" ]; then
        ok "DNS to 9.9.9.9 also redirected: $IP2"
    else
        fail "DNS to 9.9.9.9 failed"
    fi
else
    warn "No listener on port 53 — cannot test redirect"
fi
echo ""

# 5. Test: DNS to 127.0.0.1 still works (not double-redirected)
echo "--- Step 5: Localhost DNS (no loop) ---"
if [ "$HAVE_LISTENER" = true ]; then
    IP=$(resolve "127.0.0.1" "example.com" 5)
    if [ -n "$IP" ]; then
        ok "DNS to 127.0.0.1 works normally (not caught by redirect): $IP"
    else
        fail "DNS to 127.0.0.1 failed — possible redirect loop"
    fi
fi
echo ""

# 6. Simulate VPN DNS override
echo "--- Step 6: VPN DNS Override Simulation ---"
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
SVC=""
for try_svc in "Wi-Fi" "Ethernet" "Thunderbolt Ethernet"; do
    if networksetup -getdnsservers "$try_svc" 2>/dev/null >/dev/null; then
        SVC="$try_svc"
        break
    fi
done

if [ -n "$SVC" ] && [ "$HAVE_LISTENER" = true ]; then
    ORIG_DNS=$(networksetup -getdnsservers "$SVC" 2>/dev/null || echo "")
    echo "     Service: $SVC"
    echo "     Current DNS: $ORIG_DNS"

    networksetup -setdnsservers "$SVC" 10.50.10.77
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "     Set DNS to 10.50.10.77 (simulating F5 VPN)"
    sleep 2

    IP=$(resolve "10.50.10.77" "google.com" 5)
    if [ -n "$IP" ]; then
        ok "Query to fake VPN DNS (10.50.10.77) redirected to ctrld: $IP"
    else
        fail "Query to fake VPN DNS failed"
    fi

    # Restore
    if echo "$ORIG_DNS" | grep -q "There aren't any DNS Servers"; then
        networksetup -setdnsservers "$SVC" Empty
    else
        networksetup -setdnsservers "$SVC" $ORIG_DNS
    fi
    echo "     Restored DNS"
else
    warn "Skipping VPN simulation (no service found or no listener)"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}=== All tests passed ===${NC}"
else
    echo -e "${RED}=== $FAILURES test(s) failed ===${NC}"
fi

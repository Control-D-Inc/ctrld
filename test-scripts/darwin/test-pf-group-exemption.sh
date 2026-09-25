#!/bin/bash
# Test: pf group-based exemption for DNS intercept
# Run as root: sudo bash test-pf-group-exemption.sh

set -e

GROUP_NAME="_ctrld"
ANCHOR="com.controld.test"
TEST_DNS="1.1.1.1"

echo "=== Step 1: Create test group ==="
if dscl . -read /Groups/$GROUP_NAME PrimaryGroupID &>/dev/null; then
    echo "Group $GROUP_NAME already exists"
else
    # Find an unused GID in 350-450 range
    USED_GIDS=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n)
    GROUP_ID=""
    for gid in $(seq 350 450); do
        if ! echo "$USED_GIDS" | grep -q "^${gid}$"; then
            GROUP_ID=$gid
            break
        fi
    done
    if [ -z "$GROUP_ID" ]; then
        echo "ERROR: Could not find unused GID in 350-450 range"
        exit 1
    fi
    dscl . -create /Groups/$GROUP_NAME
    dscl . -create /Groups/$GROUP_NAME PrimaryGroupID $GROUP_ID
    dscl . -create /Groups/$GROUP_NAME RealName "Control D DNS Intercept"
    echo "Created group $GROUP_NAME (GID $GROUP_ID)"
fi

ACTUAL_GID=$(dscl . -read /Groups/$GROUP_NAME PrimaryGroupID | awk '{print $2}')
echo "GID: $ACTUAL_GID"

echo ""
echo "=== Step 2: Enable pf ==="
pfctl -e 2>&1 || true

echo ""
echo "=== Step 3: Set up pf anchor with group exemption ==="

cat > /tmp/pf-group-test-anchor.conf << RULES
# Translation: redirect DNS on loopback to our listener
rdr pass on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53
rdr pass on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53

# Exemption: only group _ctrld can talk to $TEST_DNS directly
pass out quick on ! lo0 inet proto { udp, tcp } from any to $TEST_DNS port 53 group $GROUP_NAME

# Intercept everything else
pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53
pass out quick on ! lo0 route-to lo0 inet proto tcp from any to ! 127.0.0.1 port 53
pass in quick on lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53
RULES

pfctl -a $ANCHOR -f /tmp/pf-group-test-anchor.conf 2>/dev/null
echo "Loaded anchor $ANCHOR"

# Inject anchor refs into running ruleset
NAT_RULES=$(pfctl -sn 2>/dev/null | grep -v "ALTQ" | grep -v "^$")
FILTER_RULES=$(pfctl -sr 2>/dev/null | grep -v "ALTQ" | grep -v "^$")
SCRUB_RULES=$(echo "$FILTER_RULES" | grep "^scrub" || true)
PURE_FILTER=$(echo "$FILTER_RULES" | grep -v "^scrub" | grep -v "com.controld.test" || true)
CLEAN_NAT=$(echo "$NAT_RULES" | grep -v "com.controld.test" || true)

{
    [ -n "$SCRUB_RULES" ] && echo "$SCRUB_RULES"
    [ -n "$CLEAN_NAT" ] && echo "$CLEAN_NAT"
    echo "rdr-anchor \"$ANCHOR\""
    echo "anchor \"$ANCHOR\""
    [ -n "$PURE_FILTER" ] && echo "$PURE_FILTER"
} | pfctl -f - 2>/dev/null

echo "Injected anchor references (no duplicates)"

echo ""
echo "=== Step 4: Verify rules ==="
echo "NAT rules:"
pfctl -sn 2>/dev/null | grep -v ALTQ
echo ""
echo "Anchor filter rules:"
pfctl -a $ANCHOR -sr 2>/dev/null | grep -v ALTQ
echo ""
echo "Anchor NAT rules:"
pfctl -a $ANCHOR -sn 2>/dev/null | grep -v ALTQ

echo ""
echo "=== Step 5: Build setgid test binary ==="
# We need a binary that runs with effective group _ctrld.
# sudo -g doesn't work on macOS, so we use a setgid binary.
cat > /tmp/test-dns-group.c << 'EOF'
#include <unistd.h>
int main() {
    char *args[] = {"dig", "+short", "+timeout=3", "+tries=1", "@1.1.1.1", "popads.net", NULL};
    execvp("dig", args);
    return 1;
}
EOF
cc -o /tmp/test-dns-group /tmp/test-dns-group.c
chgrp $GROUP_NAME /tmp/test-dns-group
chmod g+s /tmp/test-dns-group
echo "Built setgid binary /tmp/test-dns-group (group: $GROUP_NAME)"

echo ""
echo "=== Step 6: Test as regular user (should be INTERCEPTED) ==="
echo "Running: dig @$TEST_DNS popads.net (as root / group wheel — no group exemption)"
echo "If nothing listens on 127.0.0.1:53, this should timeout."
DIG_RESULT=$(dig +short +timeout=3 +tries=1 @$TEST_DNS popads.net 2>&1 || true)
echo "Result: ${DIG_RESULT:-TIMEOUT/INTERCEPTED}"

echo ""
echo "=== Step 7: Test as group _ctrld (should BYPASS) ==="
echo "Running: setgid binary (effective group: $GROUP_NAME)"
BYPASS_RESULT=$(/tmp/test-dns-group 2>&1 || true)
echo "Result: ${BYPASS_RESULT:-TIMEOUT/BLOCKED}"

echo ""
echo "=== Results ==="
PASS=true
if [[ -z "$DIG_RESULT" || "$DIG_RESULT" == *"timed out"* || "$DIG_RESULT" == *"connection refused"* ]]; then
    echo "✅ Regular query INTERCEPTED (redirected away from $TEST_DNS)"
else
    echo "❌ Regular query NOT intercepted — got: $DIG_RESULT"
    PASS=false
fi

if [[ -n "$BYPASS_RESULT" && "$BYPASS_RESULT" != *"timed out"* && "$BYPASS_RESULT" != *"connection refused"* && "$BYPASS_RESULT" != *"TIMEOUT"* ]]; then
    echo "✅ Group _ctrld query BYPASSED — got: $BYPASS_RESULT"
else
    echo "❌ Group _ctrld query was also intercepted — got: ${BYPASS_RESULT:-TIMEOUT}"
    PASS=false
fi

if $PASS; then
    echo ""
    echo "🎉 GROUP EXEMPTION WORKS — this approach is viable for dns-intercept mode"
fi

echo ""
echo "=== Cleanup ==="
pfctl -a $ANCHOR -F all 2>/dev/null
pfctl -f /etc/pf.conf 2>/dev/null
rm -f /tmp/pf-group-test-anchor.conf /tmp/test-dns-group /tmp/test-dns-group.c
echo "Cleaned up. Group $GROUP_NAME left in place."
echo "To remove: sudo dscl . -delete /Groups/$GROUP_NAME"

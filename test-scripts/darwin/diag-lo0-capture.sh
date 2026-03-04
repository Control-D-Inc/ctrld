#!/bin/bash
# diag-lo0-capture.sh — Capture DNS on lo0 to see where the pf chain breaks
# Usage: sudo bash diag-lo0-capture.sh
# Run while VPN + ctrld are both active, then dig from another terminal

set -u
PCAP="/tmp/lo0-dns-$(date +%s).pcap"
echo "=== lo0 DNS Packet Capture ==="
echo "Capturing to: $PCAP"
echo ""

# Show current rules (verify build)
echo "--- ctrld anchor rdr rules ---"
pfctl -a com.controld.ctrld -sn 2>/dev/null
echo ""
echo "--- ctrld anchor filter rules (lo0 only) ---"
pfctl -a com.controld.ctrld -sr 2>/dev/null | grep lo0
echo ""

# Check pf state table for port 53 before
echo "--- port 53 states BEFORE dig ---"
pfctl -ss 2>/dev/null | grep ':53' | head -10
echo "(total: $(pfctl -ss 2>/dev/null | grep -c ':53'))"
echo ""

# Start capture on lo0
echo "Starting tcpdump on lo0 port 53..."
echo ">>> In another terminal, run: dig example.com"
echo ">>> Then press Ctrl-C here"
echo ""
tcpdump -i lo0 -n -v port 53 -w "$PCAP" 2>&1 &
TCPDUMP_PID=$!

# Also show live output
tcpdump -i lo0 -n port 53 2>&1 &
LIVE_PID=$!

# Wait for Ctrl-C
trap "kill $TCPDUMP_PID $LIVE_PID 2>/dev/null; echo ''; echo '--- port 53 states AFTER dig ---'; pfctl -ss 2>/dev/null | grep ':53' | head -20; echo '(total: '$(pfctl -ss 2>/dev/null | grep -c ':53')')'; echo ''; echo 'Capture saved to: $PCAP'; echo 'Read with: tcpdump -r $PCAP -n -v'; exit 0" INT
wait

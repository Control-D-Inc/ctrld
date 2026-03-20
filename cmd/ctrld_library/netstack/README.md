# Netstack - Full Packet Capture for Mobile VPN

Complete TCP/UDP/DNS packet capture implementation using gVisor netstack for Android and iOS.

## Overview

Provides full packet capture for mobile VPN applications:
- **DNS filtering** through ControlD proxy
- **IP whitelisting** - only allows connections to DNS-resolved IPs
- **TCP forwarding** for all TCP traffic (with whitelist enforcement)
- **UDP forwarding** with session tracking (with whitelist enforcement)
- **QUIC blocking** for better content filtering

## Master Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          MOBILE APP (Android/iOS)                             │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        VPN Configuration                             │    │
│  │                                                                      │    │
│  │  Android:                          iOS:                             │    │
│  │  ┌──────────────────────┐         ┌──────────────────────┐         │    │
│  │  │ Builder()            │         │ NEIPv4Settings       │         │    │
│  │  │  .addAddress(        │         │  addresses: [        │         │    │
│  │  │    "10.0.0.2", 24)   │         │    "10.0.0.2"]       │         │    │
│  │  │  .addDnsServer(      │         │                      │         │    │
│  │  │    "10.0.0.1")       │         │ NEDNSSettings        │         │    │
│  │  │                      │         │  servers: [          │         │    │
│  │  │  FIREWALL MODE:      │         │    "10.0.0.1"]       │         │    │
│  │  │  .addRoute(          │         │                      │         │    │
│  │  │    "0.0.0.0", 0)     │         │ FIREWALL MODE:       │         │    │
│  │  │                      │         │  includedRoutes:     │         │    │
│  │  │  DNS-ONLY MODE:      │         │   [.default()]       │         │    │
│  │  │  .addRoute(          │         │                      │         │    │
│  │  │    "10.0.0.1", 32)   │         │ DNS-ONLY MODE:       │         │    │
│  │  │                      │         │  includedRoutes:     │         │    │
│  │  │  .addDisallowedApp(  │         │   [10.0.0.1/32]      │         │    │
│  │  │    "com.controld.*") │         │                      │         │    │
│  │  └──────────────────────┘         └──────────────────────┘         │    │
│  │                                                                      │    │
│  │  Result:                                                             │    │
│  │  • Firewall: ALL traffic → VPN                                      │    │
│  │  • DNS-only: ONLY DNS (port 53) → VPN                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────┬───────────────────────────────────────────────────┘
                           │ Packets
                           ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                     GOMOBILE LIBRARY (ctrld_library)                         │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              PacketCaptureController.StartWithPacketCapture()        │    │
│  │                                                                      │    │
│  │  Parameters:                                                         │    │
│  │  • tunAddress: "10.0.0.1" (gateway)                                 │    │
│  │  • deviceAddress: "10.0.0.2" (device IP)                            │    │
│  │  • dnsProxyAddress: "127.0.0.1:5354" (Android) / ":53" (iOS)       │    │
│  │  • cdUID, upstreamProto, etc.                                       │    │
│  └──────────────────────────┬──────────────────────────────────────────┘    │
│                             │                                                │
│                             ↓                                                │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │                    NETSTACK CONTROLLER                            │       │
│  │                                                                   │       │
│  │  Components:                                                      │       │
│  │  ┌────────────────┐  ┌─────────────┐  ┌──────────────┐          │       │
│  │  │  DNS Filter    │  │ IP Tracker  │  │ TCP Forwarder│          │       │
│  │  │  (port 53)     │  │ (5min TTL)  │  │ (firewall)   │          │       │
│  │  └────────────────┘  └─────────────┘  └──────────────┘          │       │
│  │  ┌────────────────┐                                               │       │
│  │  │  UDP Forwarder │                                               │       │
│  │  │  (firewall)    │                                               │       │
│  │  └────────────────┘                                               │       │
│  └──────────────────────────┬───────────────────────────────────────┘       │
└─────────────────────────────┼───────────────────────────────────────────────┘
                              │
                              ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                          PACKET FLOW DETAILS                                  │
│                                                                               │
│  INCOMING PACKET (from TUN)                                                  │
│         │                                                                     │
│         ├──→ Is DNS? (port 53)                                               │
│         │   ├─ YES → DNS Filter                                              │
│         │   │         ├─→ Forward to ControlD DNS Proxy                      │
│         │   │         │   (127.0.0.1:5354 or 127.0.0.1:53)                  │
│         │   │         ├─→ Get DNS response                                   │
│         │   │         ├─→ Extract A/AAAA records                             │
│         │   │         ├─→ TrackIP() for each resolved IP                     │
│         │   │         │   • Store: resolvedIPs["93.184.216.34"] = now+5min  │
│         │   │         └─→ Return DNS response to app                         │
│         │   │                                                                 │
│         │   └─ NO → Is TCP/UDP?                                              │
│         │           │                                                         │
│         │           ├──→ TCP Packet                                          │
│         │           │     ├─→ Extract destination IP                         │
│         │           │     ├─→ Check: ipTracker.IsTracked(destIP)            │
│         │           │     │   ├─ NOT TRACKED → BLOCK                        │
│         │           │     │   │   Log: "BLOCKED hardcoded IP"                │
│         │           │     │   │   Return (connection reset)                  │
│         │           │     │   │                                              │
│         │           │     │   └─ TRACKED → ALLOW                            │
│         │           │     │       net.Dial("tcp", destIP)                    │
│         │           │     │       Bidirectional copy (app ↔ internet)        │
│         │           │     │                                                  │
│         │           └──→ UDP Packet                                          │
│         │                 ├─→ Is QUIC? (port 443/80)                         │
│         │                 │   └─ YES → BLOCK (force TCP fallback)           │
│         │                 │                                                  │
│         │                 ├─→ Extract destination IP                         │
│         │                 ├─→ Check: ipTracker.IsTracked(destIP)            │
│         │                 │   ├─ NOT TRACKED → BLOCK                        │
│         │                 │   │   Log: "BLOCKED hardcoded IP"                │
│         │                 │   │   Return (drop packet)                       │
│         │                 │   │                                              │
│         │                 │   └─ TRACKED → ALLOW                            │
│         │                 │       net.Dial("udp", destIP)                    │
│         │                 │       Forward packets (app ↔ internet)           │
│         │                 │       30s timeout per session                    │
│         │                                                                     │
│  IP TRACKER STATE (in-memory map):                                           │
│  ┌────────────────────────────────────────────────────────────┐             │
│  │ resolvedIPs map:                                            │             │
│  │                                                             │             │
│  │ "93.184.216.34"  → expires: 2026-03-20 23:35:00           │             │
│  │ "2606:2800:220::1" → expires: 2026-03-20 23:36:15         │             │
│  │ "8.8.8.8"        → expires: 2026-03-20 23:37:42           │             │
│  │                                                             │             │
│  │ Cleanup: Every 30 seconds, remove expired entries          │             │
│  │ TTL: 5 minutes (configurable)                              │             │
│  └────────────────────────────────────────────────────────────┘             │
│                                                                               │
│  EXAMPLE SCENARIO:                                                            │
│  ───────────────────────────────────────────────────────────────────────     │
│                                                                               │
│  T=0s:  App tries: connect(1.2.3.4:443)                                     │
│         → IsTracked(1.2.3.4)? NO                                             │
│         → ❌ BLOCKED                                                          │
│                                                                               │
│  T=1s:  App queries: DNS "example.com"                                       │
│         → Response: A 93.184.216.34                                          │
│         → TrackIP(93.184.216.34) with TTL=5min                               │
│                                                                               │
│  T=2s:  App tries: connect(93.184.216.34:443)                               │
│         → IsTracked(93.184.216.34)? YES (expires T+301s)                    │
│         → ✅ ALLOWED                                                          │
│                                                                               │
│  T=302s: App tries: connect(93.184.216.34:443)                              │
│          → IsTracked(93.184.216.34)? NO (expired)                            │
│          → ❌ BLOCKED (must do DNS again)                                     │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                     MODE COMPARISON (Firewall vs DNS-only)                    │
│                                                                               │
│  ┌─────────────────────────────────┬─────────────────────────────────┐      │
│  │       FIREWALL MODE             │         DNS-ONLY MODE           │      │
│  │  (Default Routes Configured)    │   (Only DNS Route Configured)   │      │
│  ├─────────────────────────────────┼─────────────────────────────────┤      │
│  │ Routes (Android):               │ Routes (Android):               │      │
│  │ • addRoute("0.0.0.0", 0)        │ • addRoute("10.0.0.1", 32)     │      │
│  │                                 │                                 │      │
│  │ Routes (iOS):                   │ Routes (iOS):                   │      │
│  │ • includedRoutes: [.default()]  │ • includedRoutes:               │      │
│  │                                 │   [10.0.0.1/32]                 │      │
│  ├─────────────────────────────────┼─────────────────────────────────┤      │
│  │ Traffic Sent to VPN:            │ Traffic Sent to VPN:            │      │
│  │ ✅ DNS (port 53)                 │ ✅ DNS (port 53)                 │      │
│  │ ✅ TCP (all ports)               │ ❌ TCP (bypasses VPN)            │      │
│  │ ✅ UDP (all ports)               │ ❌ UDP (bypasses VPN)            │      │
│  ├─────────────────────────────────┼─────────────────────────────────┤      │
│  │ IP Tracker Behavior:            │ IP Tracker Behavior:            │      │
│  │ • Tracks DNS-resolved IPs       │ • Tracks DNS-resolved IPs       │      │
│  │ • Blocks hardcoded TCP/UDP IPs  │ • No TCP/UDP to block           │      │
│  │ • Enforces DNS-first policy     │ • N/A (no non-DNS traffic)      │      │
│  ├─────────────────────────────────┼─────────────────────────────────┤      │
│  │ Use Case:                       │ Use Case:                       │      │
│  │ • Full content filtering        │ • DNS filtering only            │      │
│  │ • Block DNS bypass attempts     │ • Minimal battery impact        │      │
│  │ • Enforce ControlD policies     │ • Fast web browsing             │      │
│  └─────────────────────────────────┴─────────────────────────────────┘      │
│                                                                               │
│  MODE SWITCHING:                                                              │
│  • Android: VpnController.setFirewallMode(enabled) → recreates VPN           │
│  • iOS: sendProviderMessage("set_firewall_mode") → updates routes            │
│  • Both: No app restart needed                                               │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                    DETAILED PACKET FLOW (Firewall Mode)                       │
│                                                                               │
│  1. APP MAKES REQUEST                                                         │
│  ───────────────────────────────────────────────────────────────────────     │
│  App: connect("example.com", 443)                                            │
│    ↓                                                                          │
│  OS: Perform DNS lookup for "example.com"                                    │
│    ↓                                                                          │
│  OS: Send DNS query to VPN DNS server (10.0.0.1)                             │
│                                                                               │
│  2. DNS PACKET FLOW                                                           │
│  ───────────────────────────────────────────────────────────────────────     │
│  [DNS Query Packet: 10.0.0.2:12345 → 10.0.0.1:53]                           │
│    ↓                                                                          │
│  TUN Interface → readPacket()                                                │
│    ↓                                                                          │
│  DNSFilter.ProcessPacket()                                                   │
│    ├─ Detect port 53 (DNS)                                                   │
│    ├─ Extract DNS payload                                                    │
│    ├─ Forward to ControlD DNS proxy (127.0.0.1:5354 or :53)                 │
│    │   ↓                                                                      │
│    │  ControlD DNS Proxy                                                     │
│    │   ├─ Apply filtering rules                                              │
│    │   ├─ Query upstream DNS (DoH/DoT/DoQ)                                   │
│    │   └─ Return response: A 93.184.216.34                                   │
│    │   ↓                                                                      │
│    ├─ Parse DNS response                                                     │
│    ├─ extractAndTrackIPs()                                                   │
│    │   └─ IPTracker.TrackIP(93.184.216.34)                                  │
│    │       • Store: resolvedIPs["93.184.216.34"] = now + 5min               │
│    ├─ Build DNS response packet                                              │
│    └─ writePacket() → TUN → App                                              │
│                                                                               │
│  OS receives DNS response → resolves "example.com" to 93.184.216.34         │
│                                                                               │
│  3. TCP CONNECTION FLOW                                                       │
│  ───────────────────────────────────────────────────────────────────────     │
│  OS: connect(93.184.216.34:443)                                              │
│    ↓                                                                          │
│  [TCP SYN Packet: 10.0.0.2:54321 → 93.184.216.34:443]                       │
│    ↓                                                                          │
│  TUN Interface → readPacket()                                                │
│    ↓                                                                          │
│  gVisor Netstack → TCPForwarder.handleConnection()                           │
│    ├─ Extract destination IP: 93.184.216.34                                  │
│    ├─ Check internal VPN subnet (10.0.0.0/24)?                              │
│    │   └─ NO (skip check)                                                    │
│    ├─ ipTracker.IsTracked(93.184.216.34)?                                   │
│    │   ├─ Check resolvedIPs map                                              │
│    │   ├─ Found: expires at T+300s                                           │
│    │   ├─ Not expired yet                                                    │
│    │   └─ YES ✅                                                              │
│    ├─ ALLOWED - create upstream connection                                   │
│    ├─ net.Dial("tcp", "93.184.216.34:443")                                  │
│    │   ↓                                                                      │
│    │  [Real Network Connection]                                              │
│    │   ↓                                                                      │
│    └─ Bidirectional copy (TUN ↔ Internet)                                    │
│                                                                               │
│  4. BLOCKED SCENARIO (Hardcoded IP)                                           │
│  ───────────────────────────────────────────────────────────────────────     │
│  App: connect(1.2.3.4:443)  // Hardcoded IP, no DNS!                        │
│    ↓                                                                          │
│  [TCP SYN Packet: 10.0.0.2:54322 → 1.2.3.4:443]                             │
│    ↓                                                                          │
│  TUN Interface → readPacket()                                                │
│    ↓                                                                          │
│  gVisor Netstack → TCPForwarder.handleConnection()                           │
│    ├─ Extract destination IP: 1.2.3.4                                        │
│    ├─ ipTracker.IsTracked(1.2.3.4)?                                         │
│    │   └─ Check resolvedIPs map → NOT FOUND                                 │
│    │   └─ NO ❌                                                               │
│    ├─ BLOCKED                                                                 │
│    ├─ Log: "[TCP] BLOCKED hardcoded IP: 10.0.0.2:54322 → 1.2.3.4:443"      │
│    └─ Return (send TCP RST to app)                                           │
│                                                                               │
│  App receives connection refused/reset                                       │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                         PLATFORM-SPECIFIC DETAILS                             │
│                                                                               │
│  ANDROID                                                                      │
│  ────────────────────────────────────────────────────────────────────────    │
│  • VPN Config: ControlDService.kt                                            │
│  • Packet I/O: FileInputStream/FileOutputStream on VPN fd                    │
│  • DNS Proxy: Listens on 0.0.0.0:5354 (connects via 127.0.0.1:5354)        │
│  • Self-Exclusion: addDisallowedApplication(packageName)                     │
│  • Mode Switch: Recreates VPN interface with new routes                      │
│  • No routing loops: App traffic bypasses VPN                                │
│                                                                               │
│  IOS                                                                          │
│  ────────────────────────────────────────────────────────────────────────    │
│  • VPN Config: PacketTunnelProvider.swift                                    │
│  • Packet I/O: NEPacketTunnelFlow (async → blocking via PacketQueue)        │
│  • DNS Proxy: Listens on 127.0.0.1:53                                       │
│  • Self-Exclusion: Network Extension sockets auto-bypass                     │
│  • Mode Switch: setTunnelNetworkSettings() with new routes                   │
│  • Write Batching: 16 packets per batch, 5ms flush timer                     │
│  • No routing loops: Extension traffic bypasses VPN                          │
└──────────────────────────────────────────────────────────────────────────────┘

## Components

### DNS Filter (`dns_filter.go`)
- Detects DNS packets on port 53 (UDP/TCP)
- Forwards to ControlD DNS proxy (via DNS bridge)
- Parses DNS responses to extract A/AAAA records
- Automatically tracks resolved IPs via IP Tracker
- Builds DNS response packets and sends back to TUN

### DNS Bridge (`dns_bridge.go`)
- Bridges between netstack and ControlD DNS proxy
- Tracks DNS queries by transaction ID
- 5-second timeout per query
- Returns responses to DNS filter

### IP Tracker (`ip_tracker.go`)
- **Always enabled** - tracks all DNS-resolved IPs
- In-memory whitelist with 5-minute TTL per IP
- Background cleanup every 30 seconds (removes expired IPs)
- Thread-safe with RWMutex (optimized for read-heavy workload)
- Used by TCP/UDP forwarders to enforce DNS-first policy

### TCP Forwarder (`tcp_forwarder.go`)
- Handles TCP connections via gVisor's `tcp.NewForwarder()`
- Checks `ipTracker != nil` (always true) for firewall enforcement
- Allows internal VPN subnet (10.0.0.0/24) without checks
- Blocks connections to non-tracked IPs (logs: "BLOCKED hardcoded IP")
- Forwards allowed connections via `net.Dial("tcp")` to real network
- Bidirectional copy between TUN and internet

### UDP Forwarder (`udp_forwarder.go`)
- Handles UDP packets via gVisor's `udp.NewForwarder()`
- Session tracking with 30-second read timeout
- Checks `ipTracker != nil` (always true) for firewall enforcement
- Blocks QUIC (UDP/443, UDP/80) to force TCP fallback
- Blocks connections to non-tracked IPs (logs: "BLOCKED hardcoded IP")
- Forwards allowed packets via `net.Dial("udp")` to real network

### Packet Handler (`packet_handler.go`)
- Interface for TUN I/O operations (read, write, close)
- `MobilePacketHandler` wraps mobile platform callbacks
- Bridges gomobile interface with netstack

### Netstack Controller (`netstack.go`)
- Manages gVisor TCP/IP stack
- Coordinates DNS Filter, IP Tracker, TCP/UDP Forwarders
- Always creates IP Tracker (firewall always on)
- Reads packets from TUN → injects into netstack
- Writes packets from netstack → sends to TUN
- Filters outbound packets (source = 10.0.0.x)
- Blocks QUIC before injection into netstack

## Platform Configuration

### Android

```kotlin
// Base VPN configuration (same for both modes)
Builder()
    .addAddress("10.0.0.2", 24)
    .addDnsServer("10.0.0.1")
    .setMtu(1500)
    .setBlocking(true)
    .addDisallowedApplication(packageName)  // Exclude self from VPN!

// Firewall mode - route ALL traffic
if (isFirewallMode) {
    vpnBuilder.addRoute("0.0.0.0", 0)
}
// DNS-only mode - route ONLY DNS server IP
else {
    vpnBuilder.addRoute("10.0.0.1", 32)
}

vpnInterface = vpnBuilder.establish()

// DNS Proxy listens on: 0.0.0.0:5354
// Library connects to: 127.0.0.1:5354
```

**Important:**
- App MUST exclude itself using `addDisallowedApplication()` to prevent routing loops
- Mode switching: Call `setFirewallMode(enabled)` to recreate VPN interface with new routes

### iOS

```swift
// Base configuration (same for both modes)
let ipv4Settings = NEIPv4Settings(
    addresses: ["10.0.0.2"],
    subnetMasks: ["255.255.255.0"]
)

// Firewall mode - route ALL traffic
if isFirewallMode {
    ipv4Settings.includedRoutes = [NEIPv4Route.default()]
}
// DNS-only mode - route ONLY DNS server IP
else {
    ipv4Settings.includedRoutes = [
        NEIPv4Route(destinationAddress: "10.0.0.1", subnetMask: "255.255.255.255")
    ]
}

let dnsSettings = NEDNSSettings(servers: ["10.0.0.1"])
dnsSettings.matchDomains = [""]

networkSettings.ipv4Settings = ipv4Settings
networkSettings.dnsSettings = dnsSettings
networkSettings.mtu = 1500

setTunnelNetworkSettings(networkSettings)

// DNS Proxy listens on: 127.0.0.1:53
// Library connects to: 127.0.0.1:53
```

**Note:**
- Network Extension sockets automatically bypass VPN - no routing loops
- Mode switching: Send message `{"action": "set_firewall_mode", "enabled": "true"}` to extension

## Protocol Support

| Protocol | Support |
|----------|---------|
| DNS (UDP/TCP port 53) | ✅ Full |
| TCP (all ports) | ✅ Full |
| UDP (except 53, 80, 443) | ✅ Full |
| QUIC (UDP/443, UDP/80) | 🚫 Blocked |
| ICMP | ⚠️ Partial |
| IPv4 | ✅ Full |
| IPv6 | ✅ Full |

## QUIC Blocking

Blocks UDP packets on ports 443 and 80 to force TCP fallback.

**Where it's blocked:**
- `netstack.go:354-369` - Blocks QUIC **before** injection into gVisor stack
- Early blocking (pre-netstack) for efficiency
- Checks destination port (UDP/443, UDP/80) in raw packet

**Why:**
- QUIC/HTTP3 can use cached IPs, bypassing DNS filtering entirely
- TCP/TLS provides visible SNI for content filtering
- Ensures consistent ControlD policy enforcement
- IP tracker alone isn't enough (apps cache QUIC IPs aggressively)

**Result:**
- Apps automatically fallback to TCP/TLS (HTTP/2, HTTP/1.1)
- No user-visible errors (fallback is seamless)
- Slightly slower initial connection, then normal performance

**Note:** IP tracker ALSO blocks hardcoded IPs, but QUIC blocking provides additional layer of protection since QUIC apps often cache IPs longer than 5 minutes.

## IP Blocking (DNS Bypass Prevention)

**Firewall is ALWAYS enabled.** The IP tracker runs in all modes and tracks all DNS-resolved IPs.

**How it works:**
1. DNS responses are parsed to extract A and AAAA records
2. Resolved IPs are tracked in memory whitelist for 5 minutes (TTL)
3. In **firewall mode**: TCP/UDP connections to **non-whitelisted** IPs are **BLOCKED**
4. In **DNS-only mode**: Only DNS traffic reaches the VPN, so IP blocking is inactive

**Mode Behavior:**
- **Firewall mode** (default routes): OS sends ALL traffic to VPN
  - DNS queries → tracked IPs
  - TCP/UDP connections → checked against tracker → blocked if not tracked

- **DNS-only mode** (DNS route only): OS sends ONLY DNS to VPN
  - DNS queries → tracked IPs
  - TCP/UDP connections → bypass VPN entirely (never reach tracker)

**Why IP tracker is always on:**
- Simplifies implementation (no enable/disable logic)
- Ready for mode switching at runtime
- In DNS-only mode, tracker tracks IPs but never blocks (no TCP/UDP traffic)

**Example (Firewall Mode):**
```
T=0s:  App connects to 1.2.3.4 directly
       → ❌ BLOCKED (not in tracker)

T=1s:  App queries "example.com" → DNS returns 93.184.216.34
       → Tracker stores: 93.184.216.34 (expires in 5min)

T=2s:  App connects to 93.184.216.34
       → ✅ ALLOWED (found in tracker, not expired)

T=302s: App connects to 93.184.216.34
        → ❌ BLOCKED (expired, must query DNS again)
```

**Components:**
- `ip_tracker.go` - Always-on whitelist with 5min TTL, 30s cleanup
- `dns_filter.go` - Extracts A/AAAA records, tracks IPs automatically
- `tcp_forwarder.go` - Checks `ipTracker != nil` (always true)
- `udp_forwarder.go` - Checks `ipTracker != nil` (always true)

## Usage (Android)

```kotlin
// Create callback
val callback = object : PacketAppCallback {
    override fun readPacket(): ByteArray { ... }
    override fun writePacket(packet: ByteArray) { ... }
    override fun closePacketIO() { ... }
    override fun exit(s: String) { ... }
    override fun hostname(): String = "android-device"
    override fun lanIp(): String = "10.0.0.2"
    override fun macAddress(): String = "00:00:00:00:00:00"
}

// Create controller
val controller = Ctrld_library.newPacketCaptureController(callback)

// Start with all parameters
controller.startWithPacketCapture(
    callback,                       // PacketAppCallback
    "10.0.0.1",                    // TUN address (gateway)
    "10.0.0.2",                    // Device address
    1500,                          // MTU
    "127.0.0.1:5354",             // DNS proxy address
    "your-cd-uid",                 // ControlD UID
    "",                            // Provision ID (optional)
    "",                            // Custom hostname (optional)
    filesDir.absolutePath,         // Home directory
    "doh",                         // Upstream protocol (doh/dot/doq)
    2,                             // Log level (0-3)
    "$filesDir/ctrld.log"          // Log path
)

// Stop
controller.stop(false, 0)

// Runtime mode switching (no restart needed)
VpnController.instance?.setFirewallMode(context, isFirewallMode = true)
```

## Usage (iOS)

```swift
// Start LocalProxy with all parameters
let proxy = LocalProxy()
proxy.mode = .firewall  // or .dnsOnly

proxy.start(
    tunAddress: "10.0.0.1",                    // TUN address (gateway)
    deviceAddress: "10.0.0.2",                 // Device address
    mtu: 1500,                                 // MTU
    dnsProxyAddress: "127.0.0.1:53",          // DNS proxy address
    cUID: cdUID,                               // ControlD UID
    provisionID: "",                           // Provision ID (optional)
    customHostname: "",                        // Custom hostname (optional)
    homeDir: FileManager().temporaryDirectory.path,  // Home directory
    upstreamProto: "doh",                      // Upstream protocol
    logLevel: 2,                               // Log level (0-3)
    logPath: FileManager().temporaryDirectory.appendingPathComponent("ctrld.log").path,
    deviceName: UIDevice.current.name,         // Device name
    packetFlow: packetFlow                     // NEPacketTunnelFlow
)

// Stop
proxy.stop()

// Runtime mode switching (no restart needed)
// Send message from main app to extension:
let message = ["action": "set_firewall_mode", "enabled": "true"]
session.sendProviderMessage(JSONEncoder().encode(message)) { response in }
```

## Requirements

- **Android**: API 24+ (Android 7.0+)
- **iOS**: iOS 12.0+
- **Go**: 1.23+
- **gVisor**: v0.0.0-20240722211153-64c016c92987

## Files

- `packet_handler.go` - TUN I/O interface
- `netstack.go` - gVisor controller
- `dns_filter.go` - DNS packet detection and IP extraction
- `dns_bridge.go` - Transaction tracking
- `ip_tracker.go` - DNS-resolved IP whitelist with TTL
- `tcp_forwarder.go` - TCP forwarding with whitelist enforcement
- `udp_forwarder.go` - UDP forwarding with whitelist enforcement

## License

Same as parent ctrld project.

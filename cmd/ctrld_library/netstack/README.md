# Netstack - Full Packet Capture for Mobile VPN

Complete TCP/UDP/DNS packet capture implementation using gVisor netstack for Android and iOS.

## Overview

Provides full packet capture for mobile VPN applications:
- **DNS filtering** through ControlD proxy
- **IP whitelisting** - only allows connections to DNS-resolved IPs
- **TCP forwarding** for all TCP traffic (with whitelist enforcement)
- **UDP forwarding** with session tracking (with whitelist enforcement)
- **Socket protection** to prevent routing loops
- **QUIC blocking** for better content filtering

## Architecture

```
Mobile Apps → VPN TUN Interface → PacketHandler → gVisor Netstack
    ↓
├─→ DNS Filter (Port 53)
│   └─→ ControlD DNS Proxy
├─→ TCP Forwarder
│   └─→ net.Dial("tcp") + protect(fd)
└─→ UDP Forwarder
    └─→ net.Dial("udp") + protect(fd)
    ↓
Real Network (Protected Sockets)
```

## Components

### DNS Filter (`dns_filter.go`)
Detects DNS packets on port 53, routes to ControlD proxy, and extracts resolved IPs.

### DNS Bridge (`dns_bridge.go`)
Tracks DNS queries by transaction ID with 5-second timeout.

### IP Tracker (`ip_tracker.go`)
Maintains whitelist of DNS-resolved IPs with 5-minute TTL.

### TCP Forwarder (`tcp_forwarder.go`)
Forwards TCP connections using gVisor's `tcp.NewForwarder()`. Blocks non-whitelisted IPs.

### UDP Forwarder (`udp_forwarder.go`)
Forwards UDP packets with 30-second read deadline. Blocks non-whitelisted IPs.

### Packet Handler (`packet_handler.go`)
Interface for TUN I/O and socket protection.

### Netstack Controller (`netstack.go`)
Manages gVisor stack and coordinates all components.

## Socket Protection

Critical for preventing routing loops:

```go
// Protection happens BEFORE connect()
dialer.Control = func(network, address string, c syscall.RawConn) error {
    return c.Control(func(fd uintptr) {
        protectSocket(int(fd))
    })
}
```

**All protected sockets:**
- TCP/UDP forwarder sockets (user traffic)
- ControlD API sockets (api.controld.com)
- DoH upstream sockets (freedns.controld.com)

## Platform Configuration

### Android

```kotlin
Builder()
    .addAddress("10.0.0.2", 24)
    .addRoute("0.0.0.0", 0)
    .addDnsServer("10.0.0.1")
    .setMtu(1500)

override fun protectSocket(fd: Long) {
    protect(fd.toInt())  // VpnService.protect()
}

// DNS Proxy: 0.0.0.0:5354
```

### iOS

```swift
NEIPv4Settings(addresses: ["10.0.0.2"], ...)
NEDNSSettings(servers: ["10.0.0.1"])
includedRoutes = [NEIPv4Route.default()]

func protectSocket(_ fd: Int) throws {
    // No action needed - iOS Network Extension sockets
    // automatically bypass VPN tunnel
}

// DNS Proxy: 127.0.0.1:53
```

**Note:** iOS Network Extensions run in separate process - sockets automatically bypass VPN.

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

Drops UDP packets on ports 443 and 80 to force TCP fallback:

**Why:**
- Better DNS filtering (QUIC bypasses DNS)
- Visible SNI for content filtering
- Consistent ControlD policy enforcement

**Result:**
- Apps automatically fallback to TCP/TLS
- No user-visible errors
- Slightly slower initial connection, then normal

## IP Blocking (DNS Bypass Prevention)

Enforces whitelist approach: ONLY allows connections to IPs resolved through ControlD DNS.

**How it works:**
1. DNS responses are parsed to extract A and AAAA records
2. Resolved IPs are tracked in memory whitelist for 5 minutes
3. TCP/UDP connections to **non-whitelisted** IPs are **BLOCKED**
4. Only IPs that went through DNS resolution are allowed

**Why:**
- Prevents DNS bypass via hardcoded/cached IPs
- Ensures ALL traffic must go through ControlD DNS first
- Blocks apps that try to skip DNS filtering
- Enforces strict ControlD policy compliance

**Example:**
```
✅ ALLOWED:  App queries "example.com" → 93.184.216.34 → connects to 93.184.216.34
❌ BLOCKED:  App connects directly to 1.2.3.4 (not resolved via DNS)
```

**Components:**
- `ip_tracker.go` - Manages whitelist of DNS-resolved IPs with TTL
- `dns_filter.go` - Extracts IPs from DNS responses for whitelist
- `tcp_forwarder.go` - Allows only whitelisted IPs, blocks others
- `udp_forwarder.go` - Allows only whitelisted IPs, blocks others

## Usage (Android)

```kotlin
// Create callback
val callback = object : PacketAppCallback {
    override fun readPacket(): ByteArray { ... }
    override fun writePacket(packet: ByteArray) { ... }
    override fun protectSocket(fd: Long) {
        protect(fd.toInt())
    }
    override fun closePacketIO() { ... }
    override fun exit(s: String) { ... }
    override fun hostname(): String = "android-device"
    override fun lanIp(): String = "10.0.0.2"
    override fun macAddress(): String = "00:00:00:00:00:00"
}

// Create controller
val controller = Ctrld_library.newPacketCaptureController(callback)

// Start
controller.startWithPacketCapture(
    callback,
    cdUID,
    "", "",
    filesDir.absolutePath,
    "doh",
    2,
    "$filesDir/ctrld.log"
)

// Stop
controller.stop(false, 0)
```

## Usage (iOS)

```swift
// DNS-only mode
let proxy = LocalProxy()
proxy.start(
    cUID: cdUID,
    deviceName: UIDevice.current.name,
    upstreamProto: "doh",
    logLevel: 3,
    provisionID: ""
)

// Firewall mode (full capture)
let proxy = LocalProxy()
proxy.startFirewall(
    cUID: cdUID,
    deviceName: UIDevice.current.name,
    upstreamProto: "doh",
    logLevel: 3,
    provisionID: "",
    packetFlow: packetFlow
)
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

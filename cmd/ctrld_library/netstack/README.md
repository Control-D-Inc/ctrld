# Netstack - Full Packet Capture for Mobile VPN

Complete TCP/UDP/DNS packet capture implementation using gVisor netstack for Android and iOS VPN apps.

## Overview

This module provides full packet capture capabilities for mobile VPN applications, handling:
- **DNS filtering** through ControlD proxy
- **TCP forwarding** for HTTP/HTTPS and all TCP traffic
- **UDP forwarding** for games, video streaming, VoIP, etc.
- **Socket protection** to prevent routing loops on Android/iOS

## Architecture

```
Mobile Apps (Browser, Games, etc)
    ↓
VPN TUN Interface
  - Device: 10.0.0.2/24
  - Gateway: 10.0.0.1
  - DNS: 10.0.0.1 (ControlD)
    ↓
PacketHandler (Read/Write/Protect)
    ↓
gVisor Netstack (10.0.0.1)
    ├─→ DNS Filter (dest port 53)
    │   ├─→ DNS Bridge (transaction ID tracking)
    │   └─→ ControlD DNS Proxy (localhost:5354)
    │       └─→ DoH Upstream (freedns.controld.com)
    │           └─→ Protected Socket → Internet
    ├─→ TCP Forwarder (non-DNS TCP traffic)
    │   ├─→ net.Dial("tcp", destination)
    │   ├─→ protect(fd) BEFORE connect()
    │   └─→ io.Copy() bidirectional
    └─→ UDP Forwarder (non-DNS UDP traffic)
        ├─→ net.Dial("udp", destination)
        ├─→ protect(fd) BEFORE connect()
        └─→ Session tracking (60s timeout)
    ↓
Real Network (WiFi/Cellular) - All Sockets Protected
```

## Key Components

### 1. DNS Filter (`dns_filter.go`)
- Detects DNS packets (UDP port 53)
- Extracts DNS query payload
- Sends to DNS bridge
- Builds DNS response packets

### 2. DNS Bridge (`dns_bridge.go`)
- Transaction ID tracking
- Query/response matching
- 5-second timeout per query
- Channel-based communication

### 3. TCP Forwarder (`tcp_forwarder.go`)
- Uses gVisor's `tcp.NewForwarder()`
- Converts gVisor endpoints to Go `net.Conn`
- Dials regular TCP sockets (no root required)
- Protects sockets using `VpnService.protect()` callback
- Bidirectional `io.Copy()` for data forwarding

### 4. UDP Forwarder (`udp_forwarder.go`)
- Uses gVisor's `udp.NewForwarder()`
- Per-session connection tracking
- Dials regular UDP sockets (no root required)
- Protected sockets prevent routing loops
- 60-second idle timeout with automatic cleanup

### 5. Packet Handler (`packet_handler.go`)
- Interface for reading/writing raw IP packets
- Mobile platforms implement:
  - `ReadPacket()` - Read from TUN file descriptor
  - `WritePacket()` - Write to TUN file descriptor
  - `ProtectSocket(fd)` - Protect socket from VPN routing
  - `Close()` - Clean up resources

### 6. Netstack Controller (`netstack.go`)
- Manages gVisor stack lifecycle
- Coordinates DNS filter and TCP/UDP forwarders
- Filters outbound packets (source=10.0.0.x)
- Drops return packets (handled by forwarders)

## Critical Design Decisions

### Socket Protection

**Why It's Critical:**
Without socket protection, outbound connections would route back through the VPN, creating infinite loops:

```
Bad (without protect):
App → VPN → TCP Forwarder → net.Dial() → VPN → TCP Forwarder → LOOP!

Good (with protect):
App → VPN → TCP Forwarder → net.Dial() → [PROTECTED] → WiFi → Internet ✅
```

**Implementation:**
```go
// Protect socket BEFORE connect() is called
dialer.Control = func(network, address string, c syscall.RawConn) error {
    return c.Control(func(fd uintptr) {
        protectSocket(int(fd))  // Android: VpnService.protect()
    })
}
```

**All Protected Sockets:**
1. **TCP forwarder sockets** - User HTTP/HTTPS traffic
2. **UDP forwarder sockets** - User games/video/VoIP traffic
3. **ControlD API sockets** - Configuration fetch (api.controld.com)
4. **DoH upstream sockets** - DNS resolution (freedns.controld.com)

**Timing is Critical:**

Protection must happen **DURING** socket creation, not after:

```go
// ✅ CORRECT - Protection happens BEFORE connect()
dialer := &net.Dialer{
    Control: func(network, address string, c syscall.RawConn) error {
        return c.Control(func(fd uintptr) {
            protectSocket(int(fd))  // Called before connect() syscall
        })
    },
}
conn, _ := dialer.Dial("tcp", "google.com:443")  // Socket already protected!

// ❌ WRONG - Protection happens AFTER connect()
conn, _ := net.Dial("tcp", "google.com:443")  // SYN already sent through VPN!
rawConn.Control(func(fd uintptr) {
    protectSocket(int(fd))  // TOO LATE - routing loop already started
})
```

### Outbound vs Return Packets

**Outbound packets** (10.0.0.x → Internet):
- Source IP: 10.0.0.x
- Injected into gVisor netstack
- Handled by TCP/UDP forwarders

**Return packets** (Internet → 10.0.0.x):
- Source IP: NOT 10.0.0.x
- Dropped by readPackets()
- Return through forwarder's upstream connection automatically

### Address Mapping in gVisor

For inbound connections to the netstack:
- `id.LocalAddress/LocalPort` = **Destination** (where packet is going TO)
- `id.RemoteAddress/RemotePort` = **Source** (where packet is coming FROM)

Therefore, we dial `LocalAddress:LocalPort` (the destination).

## Packet Flow Examples

### DNS Query (Port 53)

```
1. App queries google.com
   DNS query: 10.0.0.2:54321 → 10.0.0.1:53

2. VPN TUN captures packet
   PacketHandler.readPacket() returns raw IP packet

3. DNS Filter detects port 53
   Extracts UDP payload (DNS query bytes)

4. DNS Bridge processes query
   - Parses DNS message (transaction ID: 12345)
   - Stores in pending map
   - Sends to query channel

5. DNS Handler receives query
   - Forwards to ControlD proxy: localhost:5354
   - ControlD applies policies and filters
   - Queries DoH upstream (freedns.controld.com) via PROTECTED socket
   - Returns filtered response

6. DNS Bridge matches response
   - Finds pending query by transaction ID
   - Sends response to waiting channel

7. DNS Filter builds response packet
   - Wraps DNS bytes in UDP/IP packet
   - Swaps src/dst: 10.0.0.1:53 → 10.0.0.2:54321

8. PacketHandler writes response to TUN
   App receives DNS response with IP address
```

### TCP Connection (HTTP/HTTPS)

```
1. App connects to google.com:443
   SYN packet: 10.0.0.2:12345 → 142.250.190.78:443

2. VPN TUN captures packet
   PacketHandler.readPacket() returns raw IP packet

3. Netstack filters packet
   - Checks source IP = 10.0.0.2 (outbound? YES)
   - Not DNS (port != 53)
   - Injects into gVisor netstack

4. gVisor calls TCP forwarder
   TransportEndpointID:
   - LocalAddress: 142.250.190.78:443 (destination)
   - RemoteAddress: 10.0.0.2:12345 (source)

5. TCP Forwarder creates connection
   - Creates gonet.TCPConn (TUN side)
   - Dials net.Dial("tcp", "142.250.190.78:443")
   - Protects socket BEFORE connect() → No routing loop!
   - Connects via WiFi/Cellular (bypasses VPN)

6. Bidirectional copy
   - TUN → Upstream: io.Copy(upstreamConn, tunConn)
   - Upstream → TUN: io.Copy(tunConn, upstreamConn)
   - All HTTP data flows through protected socket

7. Connection closes when either side finishes
```

### UDP Packet (Games/Video)

```
1. Game sends UDP packet
   UDP: 10.0.0.2:54321 → game-server.com:9000

2. VPN TUN captures packet
   PacketHandler.readPacket() returns raw IP packet

3. Netstack filters packet
   - Checks source IP = 10.0.0.2 (outbound? YES)
   - Not DNS (port != 53)
   - Injects into gVisor netstack

4. gVisor calls UDP forwarder
   TransportEndpointID:
   - LocalAddress: game-server.com:9000 (destination)
   - RemoteAddress: 10.0.0.2:54321 (source)

5. UDP Forwarder creates/reuses session
   - Creates gonet.UDPConn (TUN side)
   - Dials net.Dial("udp", "game-server.com:9000")
   - Protects socket BEFORE connect() → No routing loop!
   - Connects via WiFi/Cellular (bypasses VPN)

6. Bidirectional forwarding
   - TUN → Upstream: Read from gonet, write to net.UDPConn
   - Upstream → TUN: Read from net.UDPConn, write to gonet
   - Session tracked with 60s idle timeout

7. Auto-cleanup after 60 seconds of inactivity
```

## VPN Configuration (Android)

```kotlin
val builder = Builder()
    .setSession("ControlD VPN")
    .addAddress("10.0.0.2", 24)      // Device address
    .addRoute("0.0.0.0", 0)          // Route all traffic
    .addDnsServer("10.0.0.1")        // DNS to local TUN (ControlD)
    .setMtu(1500)

vpnInterface = builder.establish()
```

**Why DNS = 10.0.0.1:**
- Apps query 10.0.0.1:53 (local TUN interface)
- Queries captured by DNS filter
- Filtered through ControlD policies
- Apps see "ControlD" as DNS provider (not Cloudflare/Google)
```

## Usage Example (Android)

```kotlin
// In VpnService.startVpn()

// 1. Create config.toml (required by ctrld)
val configFile = File(filesDir, "config.toml")
configFile.createNewFile()
configFile.writeText("")  // Empty config, uses defaults

// 2. Build VPN interface
val builder = Builder()
    .setSession("ControlD VPN")
    .addAddress("10.0.0.2", 24)
    .addRoute("0.0.0.0", 0)
    .addDnsServer("10.0.0.1")  // CRITICAL: Use local TUN for DNS
    .setMtu(1500)

vpnInterface = builder.establish()

// 3. Get TUN file descriptor streams
inputStream = FileInputStream(vpnInterface.fileDescriptor)
outputStream = FileOutputStream(vpnInterface.fileDescriptor)

// 4. Implement PacketAppCallback
val callback = object : PacketAppCallback {
    override fun readPacket(): ByteArray {
        val length = inputStream.channel.read(readBuffer)
        val packet = ByteArray(length)
        readBuffer.position(0)
        readBuffer.get(packet, 0, length)
        return packet
    }

    override fun writePacket(packet: ByteArray) {
        outputStream.write(packet)
    }

    override fun protectSocket(fd: Long) {
        // CRITICAL: Protect socket from VPN routing
        val success = protect(fd.toInt())  // VpnService.protect()
        if (!success) throw Exception("Failed to protect socket")
    }

    override fun closePacketIO() {
        inputStream?.close()
        outputStream?.close()
    }

    override fun exit(s: String) { }
    override fun hostname(): String = "android-device"
    override fun lanIp(): String = "10.0.0.2"
    override fun macAddress(): String = "00:00:00:00:00:00"
}

// 5. Create and start packet capture controller
packetController = Ctrld_library.newPacketCaptureController(callback)

packetController.startWithPacketCapture(
    callback,
    "your-cd-uid",           // From ControlD dashboard
    "",                      // Provision ID (optional)
    "",                      // Custom hostname (optional)
    filesDir.absolutePath,   // Home directory
    "doh",                   // Upstream protocol (doh/dot/os)
    2,                       // Log level (0-5)
    "${filesDir.absolutePath}/ctrld.log"
)

// 6. Stop when disconnecting
packetController.stop(false, 0)
```

## Protocol Support

| Protocol | Support | Details |
|----------|---------|---------|
| **DNS** | ✅ Full | Filtered through ControlD proxy (UDP/TCP port 53) |
| **TCP** | ✅ Full | All ports, bidirectional forwarding |
| **UDP** | ✅ Selective | All ports except 53, 80, 443 (see QUIC blocking) |
| **QUIC** | 🚫 Blocked | UDP ports 443 and 80 dropped to force TCP fallback |
| **ICMP** | ⚠️ Partial | Basic support (no forwarding yet) |
| **IPv4** | ✅ Full | Complete support |
| **IPv6** | ✅ Full | Complete support |

### QUIC Blocking

QUIC (Quick UDP Internet Connections) is blocked by dropping UDP packets on ports 443 and 80:

**Why Block QUIC:**
- QUIC bypasses traditional DNS lookups (uses Alt-Svc headers)
- Encrypts server name indication (SNI)
- Makes content filtering difficult
- Prevents some ControlD policies from working

**How It Works:**
```go
// In netstack.go readPackets()
if protocol == UDP {
    if dstPort == 443 || dstPort == 80 {
        // Drop QUIC/HTTP3 packets
        // Apps automatically fallback to TCP (HTTP/2 or HTTP/1.1)
        continue
    }
}
```

**Result:**
- Chrome/apps attempt QUIC first
- QUIC packets dropped silently
- Apps fallback to TCP/TLS (HTTP/2)
- ControlD policies work correctly
- Slightly slower initial connection, then normal speed

## Performance

| Metric | Value |
|--------|-------|
| **DNS Timeout** | 5 seconds |
| **TCP Dial Timeout** | 30 seconds |
| **UDP Idle Timeout** | 60 seconds |
| **UDP Cleanup Interval** | 30 seconds |
| **MTU** | 1500 bytes |
| **Overhead per TCP connection** | ~2KB |
| **Overhead per UDP session** | ~1KB |

## Requirements

- Go 1.23+
- gVisor netstack v0.0.0-20240722211153-64c016c92987
- For Android: API 24+ (Android 7.0+)
- For iOS: iOS 12+

## No Root Required

This implementation uses **regular TCP/UDP sockets** instead of raw sockets, making it compatible with non-rooted Android/iOS devices. Socket protection via `VpnService.protect()` (Android) or `NEPacketTunnelFlow` (iOS) prevents routing loops.

## Files

- `packet_handler.go` - Interface for TUN I/O and socket protection
- `netstack.go` - Main controller managing gVisor stack
- `dns_filter.go` - DNS packet detection and response building
- `dns_bridge.go` - DNS query/response bridging
- `tcp_forwarder.go` - TCP connection forwarding
- `udp_forwarder.go` - UDP packet forwarding with session tracking

## License

Same as parent ctrld project.

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
VPN TUN Interface (10.0.0.2/24)
    ↓
PacketHandler (Read/Write/Protect)
    ↓
gVisor Netstack (TCP/IP Stack)
    ├─→ DNS Filter (Port 53)
    │   └─→ ControlD DNS Proxy (localhost:5354)
    ├─→ TCP Forwarder
    │   └─→ net.Dial("tcp") + protect(fd)
    └─→ UDP Forwarder
        └─→ net.Dial("udp") + protect(fd)
    ↓
Real Network (WiFi/Cellular) - Protected Sockets
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
1. TCP forwarder sockets (user traffic)
2. UDP forwarder sockets (user traffic)
3. ControlD API HTTP sockets (api.controld.com)
4. DoH upstream sockets (freedns.controld.com)

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

## Usage Example (Android)

```kotlin
// In VpnService
val callback = object : PacketAppCallback {
    override fun readPacket(): ByteArray {
        // Read from TUN file descriptor
        val length = inputStream.channel.read(buffer)
        return packet
    }

    override fun writePacket(packet: ByteArray) {
        // Write to TUN file descriptor
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

// Create packet capture controller
val controller = Ctrld_library.newPacketCaptureController(callback)

// Start packet capture
controller.startWithPacketCapture(
    callback,
    "your-cd-uid",
    "", "",  // provision ID, custom hostname
    filesDir.absolutePath,
    "doh",   // upstream protocol
    2,       // log level
    "$filesDir/ctrld.log"
)

// Stop when done
controller.stop(false, 0)
```

## Protocol Support

| Protocol | Support | Details |
|----------|---------|---------|
| **DNS** | ✅ Full | Filtered through ControlD proxy |
| **TCP** | ✅ Full | All ports, bidirectional forwarding |
| **UDP** | ✅ Full | All ports except 53, session tracking |
| **ICMP** | ⚠️ Partial | Basic support (no forwarding yet) |
| **IPv4** | ✅ Full | Complete support |
| **IPv6** | ✅ Full | Complete support |

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

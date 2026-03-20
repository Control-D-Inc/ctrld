package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// Default MTU for the TUN interface
	defaultMTU = 1500

	// NICID is the ID of the network interface
	NICID = 1

	// Channel capacity for packet buffers
	channelCapacity = 512
)

// NetstackController manages the gVisor netstack integration for mobile packet capture.
type NetstackController struct {
	stack         *stack.Stack
	linkEP        *channel.Endpoint
	packetHandler PacketHandler
	dnsFilter     *DNSFilter
	ipTracker     *IPTracker
	tcpForwarder  *TCPForwarder
	udpForwarder  *UDPForwarder

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	started bool
	mu      sync.Mutex
}

// Config holds configuration for NetstackController.
type Config struct {
	// MTU is the maximum transmission unit
	MTU uint32

	// TUNIPv4 is the IPv4 address assigned to the TUN interface
	TUNIPv4 netip.Addr

	// TUNIPv6 is the IPv6 address assigned to the TUN interface (optional)
	TUNIPv6 netip.Addr

	// DNSHandler is the function to process DNS queries
	DNSHandler func([]byte) ([]byte, error)

	// UpstreamInterface is the real network interface for routing non-DNS traffic
	UpstreamInterface *net.Interface
}

// NewNetstackController creates a new netstack controller.
func NewNetstackController(handler PacketHandler, cfg *Config) (*NetstackController, error) {
	if handler == nil {
		return nil, fmt.Errorf("packet handler cannot be nil")
	}

	if cfg == nil {
		cfg = &Config{
			MTU:     defaultMTU,
			TUNIPv4: netip.MustParseAddr("10.0.0.1"),
		}
	}

	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create gVisor stack
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	// Create link endpoint
	linkEP := channel.New(channelCapacity, cfg.MTU, "")

	// Always create IP tracker (5 minute TTL for tracked IPs)
	// In firewall mode (default routes): blocks direct IP connections
	// In DNS-only mode: no non-DNS traffic to block
	ipTracker := NewIPTracker(5 * time.Minute)

	// Create DNS filter with IP tracker
	dnsFilter := NewDNSFilter(cfg.DNSHandler, ipTracker)

	// Create TCP forwarder with IP tracker
	tcpForwarder := NewTCPForwarder(s, ctx, ipTracker)

	// Create UDP forwarder with IP tracker
	udpForwarder := NewUDPForwarder(s, ctx, ipTracker)

	// Create NIC
	if err := s.CreateNIC(NICID, linkEP); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	// Enable spoofing to allow packets with any source IP
	if err := s.SetSpoofing(NICID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to enable spoofing: %v", err)
	}

	// Enable promiscuous mode to accept all packets
	if err := s.SetPromiscuousMode(NICID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to enable promiscuous mode: %v", err)
	}

	// Add IPv4 address
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(cfg.TUNIPv4.AsSlice()),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(NICID, protocolAddr, stack.AddressProperties{}); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to add IPv4 address: %v", err)
	}

	// Add IPv6 address if provided
	if cfg.TUNIPv6.IsValid() {
		protocolAddr6 := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(cfg.TUNIPv6.AsSlice()),
				PrefixLen: 64,
			},
		}
		if err := s.AddProtocolAddress(NICID, protocolAddr6, stack.AddressProperties{}); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to add IPv6 address: %v", err)
		}
	}

	// Add default routes
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         NICID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         NICID,
		},
	})

	// Register forwarders with the stack
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.forwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.forwarder.HandlePacket)

	nc := &NetstackController{
		stack:         s,
		linkEP:        linkEP,
		packetHandler: handler,
		dnsFilter:     dnsFilter,
		ipTracker:     ipTracker,
		tcpForwarder:  tcpForwarder,
		udpForwarder:  udpForwarder,
		ctx:           ctx,
		cancel:        cancel,
		started:       false,
	}

	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Controller created with TCP/UDP forwarders")

	return nc, nil
}

// Start starts the netstack controller and begins processing packets.
func (nc *NetstackController) Start() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.started {
		return fmt.Errorf("netstack controller already started")
	}

	nc.started = true

	// Start IP tracker
	nc.ipTracker.Start()

	// Start packet reader goroutine (TUN -> netstack)
	nc.wg.Add(1)
	go nc.readPackets()

	// Start packet writer goroutine (netstack -> TUN)
	nc.wg.Add(1)
	go nc.writePackets()

	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Packet processing started (read/write goroutines + IP tracker)")

	return nil
}

// Stop stops the netstack controller and waits for all goroutines to finish.
func (nc *NetstackController) Stop() error {
	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() called - starting shutdown")

	nc.mu.Lock()
	if !nc.started {
		nc.mu.Unlock()
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - already stopped, returning")
		return nil
	}
	nc.mu.Unlock()

	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - canceling context")
	nc.cancel()

	// Close packet handler FIRST to unblock all pending reads
	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - closing packet handler to unblock goroutines")
	if err := nc.packetHandler.Close(); err != nil {
		ctrld.ProxyLogger.Load().Error().Msgf("[Netstack] Stop() - failed to close packet handler: %v", err)
		// Continue shutdown even if close fails
	}
	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - packet handler closed")

	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - waiting for goroutines (max 2 seconds)")

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		nc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - all goroutines finished")
	case <-time.After(2 * time.Second):
		ctrld.ProxyLogger.Load().Warn().Msg("[Netstack] Stop() - timeout waiting for goroutines, proceeding anyway")
	}

	// Stop IP tracker
	if nc.ipTracker != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - stopping IP tracker")
		nc.ipTracker.Stop()
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - IP tracker stopped")
	}

	// Close UDP forwarder
	if nc.udpForwarder != nil {
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - closing UDP forwarder")
		nc.udpForwarder.Close()
		ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - UDP forwarder closed")
	}

	nc.mu.Lock()
	nc.started = false
	nc.mu.Unlock()

	ctrld.ProxyLogger.Load().Info().Msg("[Netstack] Stop() - shutdown complete")
	return nil
}

// readPackets reads packets from the TUN interface and injects them into the netstack.
func (nc *NetstackController) readPackets() {
	defer nc.wg.Done()

	for {
		select {
		case <-nc.ctx.Done():
			return
		default:
		}

		// Read packet from TUN
		packet, err := nc.packetHandler.ReadPacket()
		if err != nil {
			if nc.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if len(packet) == 0 {
			continue
		}

		// Check if this is a DNS packet
		isDNS, response, err := nc.dnsFilter.ProcessPacket(packet)
		if err != nil {
			continue
		}

		if isDNS && response != nil {
			// DNS packet was handled, send response back to TUN
			nc.packetHandler.WritePacket(response)
			ctrld.ProxyLogger.Load().Debug().Msgf("[Netstack] DNS response sent (%d bytes)", len(response))
			continue
		}

		if isDNS {
			continue
		}

		// Not a DNS packet - check if it's an OUTBOUND packet (source = 10.0.0.x)
		// We should ONLY inject outbound packets, not return packets
		if len(packet) >= 20 {
			// Check if source is in our VPN subnet (10.0.0.x)
			isOutbound := packet[12] == 10 && packet[13] == 0 && packet[14] == 0

			if !isOutbound {
				// This is a return packet (server -> mobile)
				// Drop it - return packets come through forwarder's upstream connection
				continue
			}

			// Block QUIC protocol (UDP on port 443)
			// QUIC runs over UDP and bypasses DNS, so we block it to force HTTP/2 or HTTP/3 over TCP
			protocol := packet[9]
			if protocol == 17 { // UDP
				// Get IP header length
				ihl := int(packet[0]&0x0f) * 4
				if len(packet) >= ihl+4 {
					// Parse UDP destination port (bytes 2-3 of UDP header)
					dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
					if dstPort == 443 || dstPort == 80 {
						// Block QUIC (UDP/443) and HTTP/3 (UDP/80)
						// Apps will fallback to TCP automatically
						dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
						ctrld.ProxyLogger.Load().Debug().Msgf("[Netstack] Blocked QUIC packet to %s:%d", dstIP, dstPort)
						continue
					}
				}
			}
		}

		// Create packet buffer
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})

		// Determine protocol number
		var proto tcpip.NetworkProtocolNumber
		if len(packet) > 0 {
			version := packet[0] >> 4
			switch version {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				pkt.DecRef()
				continue
			}
		} else {
			pkt.DecRef()
			continue
		}

		// Inject into netstack - TCP/UDP forwarders will handle it
		nc.linkEP.InjectInbound(proto, pkt)
	}
}

// writePackets reads packets from netstack and writes them to the TUN interface.
func (nc *NetstackController) writePackets() {
	defer nc.wg.Done()

	for {
		select {
		case <-nc.ctx.Done():
			return
		default:
		}

		// Read packet from netstack
		pkt := nc.linkEP.ReadContext(nc.ctx)
		if pkt == nil {
			continue
		}

		// Convert packet to bytes
		vv := pkt.ToView()
		packet := vv.AsSlice()

		// Write to TUN
		if err := nc.packetHandler.WritePacket(packet); err != nil {
			// Log error
			continue
		}

		pkt.DecRef()
	}
}

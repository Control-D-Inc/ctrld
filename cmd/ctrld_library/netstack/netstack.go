package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

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
	channelCapacity = 256
)

// NetstackController manages the gVisor netstack integration for mobile packet capture.
type NetstackController struct {
	stack         *stack.Stack
	linkEP        *channel.Endpoint
	packetHandler PacketHandler
	dnsFilter     *DNSFilter
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

	// Create DNS filter
	dnsFilter := NewDNSFilter(cfg.DNSHandler)

	// Create TCP forwarder
	tcpForwarder := NewTCPForwarder(s, handler.ProtectSocket, ctx)

	// Create UDP forwarder
	udpForwarder := NewUDPForwarder(s, handler.ProtectSocket, ctx)

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
		tcpForwarder:  tcpForwarder,
		udpForwarder:  udpForwarder,
		ctx:           ctx,
		cancel:        cancel,
		started:       false,
	}

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

	// Start packet reader goroutine (TUN -> netstack)
	nc.wg.Add(1)
	go nc.readPackets()

	// Start packet writer goroutine (netstack -> TUN)
	nc.wg.Add(1)
	go nc.writePackets()

	return nil
}

// Stop stops the netstack controller and waits for all goroutines to finish.
func (nc *NetstackController) Stop() error {
	nc.mu.Lock()
	if !nc.started {
		nc.mu.Unlock()
		return nil
	}
	nc.mu.Unlock()

	nc.cancel()
	nc.wg.Wait()

	// Close UDP forwarder
	if nc.udpForwarder != nil {
		nc.udpForwarder.Close()
	}

	if err := nc.packetHandler.Close(); err != nil {
		return fmt.Errorf("failed to close packet handler: %v", err)
	}

	nc.mu.Lock()
	nc.started = false
	nc.mu.Unlock()

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

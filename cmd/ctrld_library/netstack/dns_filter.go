package netstack

import (
	"encoding/binary"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// DNSFilter intercepts and processes DNS packets.
type DNSFilter struct {
	dnsHandler func([]byte) ([]byte, error)
}

// NewDNSFilter creates a new DNS filter with the given handler.
func NewDNSFilter(handler func([]byte) ([]byte, error)) *DNSFilter {
	return &DNSFilter{
		dnsHandler: handler,
	}
}

// ProcessPacket checks if a packet is a DNS query and processes it.
// Returns:
// - isDNS: true if this is a DNS packet
// - response: DNS response packet (if handled), nil otherwise
// - error: any error that occurred
func (df *DNSFilter) ProcessPacket(packet []byte) (isDNS bool, response []byte, err error) {
	if len(packet) < header.IPv4MinimumSize {
		return false, nil, nil
	}

	// Parse IP version
	ipVersion := packet[0] >> 4

	switch ipVersion {
	case 4:
		return df.processIPv4(packet)
	case 6:
		return df.processIPv6(packet)
	default:
		return false, nil, nil
	}
}

// processIPv4 processes an IPv4 packet and checks if it's DNS.
func (df *DNSFilter) processIPv4(packet []byte) (bool, []byte, error) {
	if len(packet) < header.IPv4MinimumSize {
		return false, nil, nil
	}

	// Parse IPv4 header
	ipHdr := header.IPv4(packet)
	if !ipHdr.IsValid(len(packet)) {
		return false, nil, nil
	}

	// Check if it's UDP
	if ipHdr.TransportProtocol() != header.UDPProtocolNumber {
		return false, nil, nil
	}

	// Get IP header length
	ihl := int(ipHdr.HeaderLength())
	if len(packet) < ihl+header.UDPMinimumSize {
		return false, nil, nil
	}

	// Parse UDP header
	udpHdr := header.UDP(packet[ihl:])
	srcPort := udpHdr.SourcePort()
	dstPort := udpHdr.DestinationPort()

	// Check if destination port is 53 (DNS)
	if dstPort != 53 {
		return false, nil, nil
	}

	srcIP := ipHdr.SourceAddress()
	dstIP := ipHdr.DestinationAddress()

	// Extract DNS payload
	udpPayloadOffset := ihl + header.UDPMinimumSize
	if len(packet) <= udpPayloadOffset {
		return true, nil, fmt.Errorf("invalid UDP packet length")
	}

	dnsQuery := packet[udpPayloadOffset:]
	if len(dnsQuery) == 0 {
		return true, nil, fmt.Errorf("empty DNS query")
	}

	// Process DNS query
	if df.dnsHandler == nil {
		return true, nil, fmt.Errorf("no DNS handler configured")
	}

	dnsResponse, err := df.dnsHandler(dnsQuery)
	if err != nil {
		return true, nil, fmt.Errorf("DNS handler error: %v", err)
	}

	// Build response packet
	responsePacket := df.buildIPv4UDPPacket(
		dstIP.As4(), // Swap src/dst
		srcIP.As4(),
		dstPort, // Swap ports
		srcPort,
		dnsResponse,
	)

	return true, responsePacket, nil
}

// processIPv6 processes an IPv6 packet and checks if it's DNS.
func (df *DNSFilter) processIPv6(packet []byte) (bool, []byte, error) {
	if len(packet) < header.IPv6MinimumSize {
		return false, nil, nil
	}

	// Parse IPv6 header
	ipHdr := header.IPv6(packet)
	if !ipHdr.IsValid(len(packet)) {
		return false, nil, nil
	}

	// Check if it's UDP
	if ipHdr.TransportProtocol() != header.UDPProtocolNumber {
		return false, nil, nil
	}

	// IPv6 header is fixed size
	if len(packet) < header.IPv6MinimumSize+header.UDPMinimumSize {
		return false, nil, nil
	}

	// Parse UDP header
	udpHdr := header.UDP(packet[header.IPv6MinimumSize:])
	srcPort := udpHdr.SourcePort()
	dstPort := udpHdr.DestinationPort()

	// Check if destination port is 53 (DNS)
	if dstPort != 53 {
		return false, nil, nil
	}

	// Extract DNS payload
	udpPayloadOffset := header.IPv6MinimumSize + header.UDPMinimumSize
	if len(packet) <= udpPayloadOffset {
		return true, nil, fmt.Errorf("invalid UDP packet length")
	}

	dnsQuery := packet[udpPayloadOffset:]
	if len(dnsQuery) == 0 {
		return true, nil, fmt.Errorf("empty DNS query")
	}

	// Process DNS query
	if df.dnsHandler == nil {
		return true, nil, fmt.Errorf("no DNS handler configured")
	}

	dnsResponse, err := df.dnsHandler(dnsQuery)
	if err != nil {
		return true, nil, fmt.Errorf("DNS handler error: %v", err)
	}

	// Build response packet
	srcIP := ipHdr.SourceAddress()
	dstIP := ipHdr.DestinationAddress()

	responsePacket := df.buildIPv6UDPPacket(
		dstIP.As16(), // Swap src/dst
		srcIP.As16(),
		dstPort, // Swap ports
		srcPort,
		dnsResponse,
	)

	return true, responsePacket, nil
}

// buildIPv4UDPPacket builds a complete IPv4/UDP packet with the given payload.
func (df *DNSFilter) buildIPv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	// Calculate lengths
	udpLen := header.UDPMinimumSize + len(payload)
	ipLen := header.IPv4MinimumSize + udpLen
	packet := make([]byte, ipLen)

	// Build IPv4 header
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srcIP),
		DstAddr:     tcpip.AddrFrom4(dstIP),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	// Build UDP header
	udpHdr := header.UDP(packet[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})

	// Copy payload
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	// Calculate UDP checksum
	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		tcpip.AddrFrom4(srcIP),
		tcpip.AddrFrom4(dstIP),
		uint16(udpLen),
	)
	xsum = checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

	return packet
}

// buildIPv6UDPPacket builds a complete IPv6/UDP packet with the given payload.
func (df *DNSFilter) buildIPv6UDPPacket(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	// Calculate lengths
	udpLen := header.UDPMinimumSize + len(payload)
	ipLen := header.IPv6MinimumSize + udpLen
	packet := make([]byte, ipLen)

	// Build IPv6 header
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(srcIP),
		DstAddr:           tcpip.AddrFrom16(dstIP),
	})

	// Build UDP header
	udpHdr := header.UDP(packet[header.IPv6MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})

	// Copy payload
	copy(packet[header.IPv6MinimumSize+header.UDPMinimumSize:], payload)

	// Calculate UDP checksum
	xsum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		tcpip.AddrFrom16(srcIP),
		tcpip.AddrFrom16(dstIP),
		uint16(udpLen),
	)
	xsum = checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

	return packet
}

// checksum calculates the checksum for the given data.
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)
	l := len(buf)
	if l&1 != 0 {
		l--
		v += uint32(buf[l]) << 8
	}
	for i := 0; i < l; i += 2 {
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
	}
	return reduceChecksum(v)
}

// reduceChecksum reduces a 32-bit checksum to 16 bits.
func reduceChecksum(v uint32) uint16 {
	v = (v >> 16) + (v & 0xffff)
	v = (v >> 16) + (v & 0xffff)
	return uint16(v)
}

// IPv4Address is a helper to create an IPv4 address from a byte array.
func IPv4Address(b [4]byte) net.IP {
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// IPv6Address is a helper to create an IPv6 address from a byte array.
func IPv6Address(b [16]byte) net.IP {
	return net.IP(b[:])
}

// parseIPv4 extracts source and destination IPs from an IPv4 packet.
func parseIPv4(packet []byte) (srcIP, dstIP [4]byte, ok bool) {
	if len(packet) < header.IPv4MinimumSize {
		return
	}
	ipHdr := header.IPv4(packet)
	if !ipHdr.IsValid(len(packet)) {
		return
	}
	srcAddr := ipHdr.SourceAddress().As4()
	dstAddr := ipHdr.DestinationAddress().As4()
	copy(srcIP[:], srcAddr[:])
	copy(dstIP[:], dstAddr[:])
	ok = true
	return
}

// parseUDP extracts UDP header information.
func parseUDP(udpHeader []byte) (srcPort, dstPort uint16, ok bool) {
	if len(udpHeader) < header.UDPMinimumSize {
		return
	}
	srcPort = binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort = binary.BigEndian.Uint16(udpHeader[2:4])
	ok = true
	return
}

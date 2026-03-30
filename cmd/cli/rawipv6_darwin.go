//go:build darwin

package cli

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/miekg/dns"
)

// wrapIPv6Handler wraps a DNS handler so that UDP responses on the [::1] listener
// are sent via raw IPv6 sockets instead of the normal sendmsg path. This is needed
// because macOS rejects sendmsg from [::1] to global unicast IPv6 addresses (EINVAL).
func wrapIPv6Handler(h dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		h.ServeDNS(&rawIPv6Writer{ResponseWriter: w}, r)
	})
}

// rawIPv6Writer wraps a dns.ResponseWriter for the [::1] IPv6 listener on macOS.
// When pf redirects IPv6 DNS traffic via route-to + rdr to [::1]:53, the original
// client source address is a global unicast IPv6 (e.g., 2607:f0c8:...). macOS
// rejects sendmsg from [::1] to any non-loopback address (EINVAL), so the normal
// WriteMsg fails. This wrapper intercepts UDP writes and sends the response via a
// raw IPv6 socket on lo0, bypassing the kernel's routing validation.
//
// TCP is not handled — IPv6 TCP DNS is blocked by pf rules and falls back to IPv4.
type rawIPv6Writer struct {
	dns.ResponseWriter
}

// WriteMsg packs the DNS message and sends it via raw socket.
func (w *rawIPv6Writer) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Write sends raw DNS response bytes via a raw IPv6/UDP socket on lo0.
// It constructs a UDP packet (header + payload) and sends it using
// IPPROTO_RAW-like behavior via IPV6_HDRINCL-free raw UDP socket.
//
// pf's rdr state table will reverse-translate the addresses on the response:
//   - src [::1]:53 → original DNS server IPv6
//   - dst [client]:port → unchanged
func (w *rawIPv6Writer) Write(payload []byte) (int, error) {
	localAddr := w.ResponseWriter.LocalAddr()
	remoteAddr := w.ResponseWriter.RemoteAddr()

	srcIP, srcPort, err := parseAddrPort(localAddr)
	if err != nil {
		return 0, fmt.Errorf("rawIPv6Writer: parse local addr %s: %w", localAddr, err)
	}
	dstIP, dstPort, err := parseAddrPort(remoteAddr)
	if err != nil {
		return 0, fmt.Errorf("rawIPv6Writer: parse remote addr %s: %w", remoteAddr, err)
	}

	// Build UDP packet: 8-byte header + DNS payload.
	udpLen := 8 + len(payload)
	udpPacket := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpPacket[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpPacket[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(udpLen))
	// Checksum placeholder — filled below.
	binary.BigEndian.PutUint16(udpPacket[6:8], 0)
	copy(udpPacket[8:], payload)

	// Compute UDP checksum over IPv6 pseudo-header + UDP packet.
	// For IPv6, UDP checksum is mandatory (unlike IPv4 where it's optional).
	csum := udp6Checksum(srcIP, dstIP, udpPacket)
	binary.BigEndian.PutUint16(udpPacket[6:8], csum)

	// Open raw UDP socket. SOCK_RAW with IPPROTO_UDP lets us send
	// hand-crafted UDP packets. The kernel adds the IPv6 header.
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return 0, fmt.Errorf("rawIPv6Writer: socket: %w", err)
	}
	defer syscall.Close(fd)

	// Bind to lo0 interface so the packet exits on loopback where pf can
	// reverse-translate via its rdr state table.
	if err := bindToLoopback6(fd); err != nil {
		return 0, fmt.Errorf("rawIPv6Writer: bind to lo0: %w", err)
	}

	// Send to the client's address.
	sa := &syscall.SockaddrInet6{Port: 0} // Port is in the UDP header, not the sockaddr for raw sockets.
	copy(sa.Addr[:], dstIP.To16())

	if err := syscall.Sendto(fd, udpPacket, 0, sa); err != nil {
		return 0, fmt.Errorf("rawIPv6Writer: sendto [%s]:%d: %w", dstIP, dstPort, err)
	}

	return len(payload), nil
}

// parseAddrPort extracts IP and port from a net.Addr (supports *net.UDPAddr and string parsing).
func parseAddrPort(addr net.Addr) (net.IP, int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok {
		return ua.IP, ua.Port, nil
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP: %s", host)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

// udp6Checksum computes the UDP checksum over the IPv6 pseudo-header and UDP packet.
// The pseudo-header includes: src IP (16), dst IP (16), UDP length (4), next header (4).
func udp6Checksum(src, dst net.IP, udpPacket []byte) uint16 {
	// IPv6 pseudo-header for checksum:
	//   Source Address (16 bytes)
	//   Destination Address (16 bytes)
	//   UDP Length (4 bytes, upper layer packet length)
	//   Zero (3 bytes) + Next Header (1 byte) = 17 (UDP)
	psh := make([]byte, 40)
	copy(psh[0:16], src.To16())
	copy(psh[16:32], dst.To16())
	binary.BigEndian.PutUint32(psh[32:36], uint32(len(udpPacket)))
	psh[39] = 17 // Next Header: UDP

	// Checksum over pseudo-header + UDP packet.
	var sum uint32
	data := append(psh, udpPacket...)
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// bindToLoopback6 binds a raw IPv6 socket to the loopback interface (lo0)
// and sets the source address to ::1. This ensures the packet exits on lo0
// where pf's rdr state can reverse-translate the addresses.
func bindToLoopback6(fd int) error {
	// Bind source to ::1 — this is the address ctrld is listening on,
	// and what pf's rdr state expects as the source of the response.
	sa := &syscall.SockaddrInet6{Port: 0}
	copy(sa.Addr[:], net.IPv6loopback.To16())
	return syscall.Bind(fd, sa)
}

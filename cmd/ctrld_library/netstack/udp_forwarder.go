package netstack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// UDPForwarder handles UDP packets from the TUN interface
type UDPForwarder struct {
	protectSocket func(fd int) error
	ctx           context.Context
	forwarder     *udp.Forwarder
	ipTracker     *IPTracker

	// Track UDP "connections" (address pairs)
	connections map[string]*udpConn
	mu          sync.Mutex
}

type udpConn struct {
	tunEP        *gonet.UDPConn
	upstreamConn *net.UDPConn
	cancel       context.CancelFunc
}

// NewUDPForwarder creates a new UDP forwarder
func NewUDPForwarder(s *stack.Stack, protectSocket func(fd int) error, ctx context.Context, ipTracker *IPTracker) *UDPForwarder {
	f := &UDPForwarder{
		protectSocket: protectSocket,
		ctx:           ctx,
		ipTracker:     ipTracker,
		connections:   make(map[string]*udpConn),
	}

	// Create gVisor UDP forwarder with handler callback
	f.forwarder = udp.NewForwarder(s, f.handlePacket)

	return f
}

// GetForwarder returns the underlying gVisor forwarder
func (f *UDPForwarder) GetForwarder() *udp.Forwarder {
	return f.forwarder
}

// handlePacket handles an incoming UDP packet
func (f *UDPForwarder) handlePacket(req *udp.ForwarderRequest) {
	// Get the endpoint ID
	id := req.ID()

	// Create connection key (source -> destination)
	connKey := fmt.Sprintf("%s:%d->%s:%d",
		net.IP(id.RemoteAddress.AsSlice()),
		id.RemotePort,
		net.IP(id.LocalAddress.AsSlice()),
		id.LocalPort,
	)

	f.mu.Lock()
	conn, exists := f.connections[connKey]
	if !exists {
		// Create new connection
		conn = f.createConnection(req, connKey)
		if conn == nil {
			f.mu.Unlock()
			return
		}
		f.connections[connKey] = conn

		// Log new UDP session
		srcAddr := net.IP(id.RemoteAddress.AsSlice())
		dstAddr := net.IP(id.LocalAddress.AsSlice())
		ctrld.ProxyLogger.Load().Debug().Msgf("[UDP] New session: %s:%d -> %s:%d (total: %d)",
			srcAddr, id.RemotePort, dstAddr, id.LocalPort, len(f.connections))
	}
	f.mu.Unlock()
}

func (f *UDPForwarder) createConnection(req *udp.ForwarderRequest, connKey string) *udpConn {
	id := req.ID()

	// Create waiter queue
	var wq waiter.Queue

	// Create endpoint from request
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		return nil
	}

	// Convert to Go UDP conn
	tunConn := gonet.NewUDPConn(&wq, ep)

	// Extract destination address
	// LocalAddress/LocalPort = destination (where packet is going TO)
	// RemoteAddress/RemotePort = source (where packet is coming FROM)
	dstIP := net.IP(id.LocalAddress.AsSlice())
	dstAddr := &net.UDPAddr{
		IP:   dstIP,
		Port: int(id.LocalPort),
	}

	// Check if IP blocking is enabled (firewall mode only)
	// Skip blocking for internal VPN subnet (10.0.0.0/24)
	if f.ipTracker != nil && f.ipTracker.IsEnabled() {
		// Allow internal VPN traffic (10.0.0.0/24)
		if !(dstIP[0] == 10 && dstIP[1] == 0 && dstIP[2] == 0) {
			// Check if destination IP was resolved through ControlD DNS
			// ONLY allow connections to IPs that went through DNS (whitelist approach)
			if !f.ipTracker.IsTracked(dstIP) {
				srcAddr := net.IP(id.RemoteAddress.AsSlice())
				ctrld.ProxyLogger.Load().Info().Msgf("[UDP] BLOCKED hardcoded IP: %s:%d -> %s:%d (not resolved via DNS)",
					srcAddr, id.RemotePort, dstIP, id.LocalPort)
				return nil
			}
		}
	}

	// Create dialer with socket protection DURING dial
	dialer := &net.Dialer{}

	// CRITICAL: Protect socket BEFORE connect() is called
	if f.protectSocket != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				f.protectSocket(int(fd))
			})
		}
	}

	// Create outbound UDP connection
	dialConn, dialErr := dialer.Dial("udp", dstAddr.String())
	if dialErr != nil {
		tunConn.Close()
		return nil
	}

	upstreamConn, ok := dialConn.(*net.UDPConn)
	if !ok {
		dialConn.Close()
		tunConn.Close()
		return nil
	}

	// Create connection context
	ctx, cancel := context.WithCancel(f.ctx)

	udpConnection := &udpConn{
		tunEP:        tunConn,
		upstreamConn: upstreamConn,
		cancel:       cancel,
	}

	// Start forwarding goroutines
	go f.forwardTunToUpstream(udpConnection, ctx)
	go f.forwardUpstreamToTun(udpConnection, ctx, connKey)

	return udpConnection
}

func (f *UDPForwarder) forwardTunToUpstream(conn *udpConn, ctx context.Context) {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from TUN
		n, err := conn.tunEP.Read(buffer)
		if err != nil {
			return
		}

		// Write to upstream
		_, err = conn.upstreamConn.Write(buffer[:n])
		if err != nil {
			return
		}
	}
}

func (f *UDPForwarder) forwardUpstreamToTun(conn *udpConn, ctx context.Context, connKey string) {
	defer func() {
		conn.tunEP.Close()
		conn.upstreamConn.Close()

		f.mu.Lock()
		delete(f.connections, connKey)
		f.mu.Unlock()
	}()

	buffer := make([]byte, 65535)

	// Set read timeout
	conn.upstreamConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from upstream
		n, err := conn.upstreamConn.Read(buffer)
		if err != nil {
			return
		}

		// Reset read deadline
		conn.upstreamConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Write to TUN
		_, err = conn.tunEP.Write(buffer[:n])
		if err != nil {
			return
		}
	}
}

// Close closes all UDP connections
func (f *UDPForwarder) Close() {
	ctrld.ProxyLogger.Load().Info().Msg("[UDP] Close() called - closing all connections")

	f.mu.Lock()
	defer f.mu.Unlock()

	ctrld.ProxyLogger.Load().Info().Msgf("[UDP] Close() - closing %d connections", len(f.connections))
	for key, conn := range f.connections {
		ctrld.ProxyLogger.Load().Debug().Msgf("[UDP] Close() - closing connection: %s", key)
		conn.cancel()
		conn.tunEP.Close()
		conn.upstreamConn.Close()
	}
	f.connections = make(map[string]*udpConn)
	ctrld.ProxyLogger.Load().Info().Msg("[UDP] Close() - all connections closed")
}

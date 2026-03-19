package netstack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

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

	// Track UDP "connections" (address pairs)
	connections map[string]*udpConn
	mu          sync.Mutex
}

type udpConn struct {
	tunEP        *gonet.UDPConn
	upstreamConn *net.UDPConn
	lastActivity time.Time
	cancel       context.CancelFunc
}

// NewUDPForwarder creates a new UDP forwarder
func NewUDPForwarder(s *stack.Stack, protectSocket func(fd int) error, ctx context.Context) *UDPForwarder {
	f := &UDPForwarder{
		protectSocket: protectSocket,
		ctx:           ctx,
		connections:   make(map[string]*udpConn),
	}

	// Create gVisor UDP forwarder with handler callback
	f.forwarder = udp.NewForwarder(s, f.handlePacket)

	// Start cleanup goroutine
	go f.cleanupStaleConnections()

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
	}
	conn.lastActivity = time.Now()
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
	dstAddr := &net.UDPAddr{
		IP:   net.IP(id.LocalAddress.AsSlice()),
		Port: int(id.LocalPort),
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
		lastActivity: time.Now(),
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

		f.mu.Lock()
		conn.lastActivity = time.Now()
		f.mu.Unlock()
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

		f.mu.Lock()
		conn.lastActivity = time.Now()
		f.mu.Unlock()
	}
}

func (f *UDPForwarder) cleanupStaleConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.mu.Lock()
			now := time.Now()
			for key, conn := range f.connections {
				if now.Sub(conn.lastActivity) > 60*time.Second {
					conn.cancel()
					conn.tunEP.Close()
					conn.upstreamConn.Close()
					delete(f.connections, key)
				}
			}
			f.mu.Unlock()
		}
	}
}

// Close closes all UDP connections
func (f *UDPForwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, conn := range f.connections {
		conn.cancel()
		conn.tunEP.Close()
		conn.upstreamConn.Close()
	}
	f.connections = make(map[string]*udpConn)
}

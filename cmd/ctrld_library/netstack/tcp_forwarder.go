package netstack

import (
	"context"
	"io"
	"net"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCPForwarder handles TCP connections from the TUN interface
type TCPForwarder struct {
	protectSocket func(fd int) error
	ctx           context.Context
	forwarder     *tcp.Forwarder
}

// NewTCPForwarder creates a new TCP forwarder
func NewTCPForwarder(s *stack.Stack, protectSocket func(fd int) error, ctx context.Context) *TCPForwarder {
	f := &TCPForwarder{
		protectSocket: protectSocket,
		ctx:           ctx,
	}

	// Create gVisor TCP forwarder with handler callback
	// rcvWnd=0 (default), maxInFlight=1024
	f.forwarder = tcp.NewForwarder(s, 0, 1024, f.handleRequest)

	return f
}

// GetForwarder returns the underlying gVisor forwarder
func (f *TCPForwarder) GetForwarder() *tcp.Forwarder {
	return f.forwarder
}

// handleRequest handles an incoming TCP connection request
func (f *TCPForwarder) handleRequest(req *tcp.ForwarderRequest) {
	// Get the endpoint ID
	id := req.ID()

	// Create waiter queue
	var wq waiter.Queue

	// Create endpoint from request
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true) // Send RST
		return
	}

	// Accept the connection
	req.Complete(false)

	// Cast to TCP endpoint
	tcpEP, ok := ep.(*tcp.Endpoint)
	if !ok {
		ep.Close()
		return
	}

	// Handle in goroutine
	go f.handleConnection(tcpEP, &wq, id)
}

func (f *TCPForwarder) handleConnection(ep *tcp.Endpoint, wq *waiter.Queue, id stack.TransportEndpointID) {
	// Convert endpoint to Go net.Conn
	tunConn := gonet.NewTCPConn(wq, ep)
	defer tunConn.Close()

	// In gVisor's TransportEndpointID for an inbound connection:
	// - LocalAddress/LocalPort = the destination (where packet is going TO)
	// - RemoteAddress/RemotePort = the source (where packet is coming FROM)
	// We want to dial the DESTINATION (LocalAddress/LocalPort)
	dstAddr := net.TCPAddr{
		IP:   net.IP(id.LocalAddress.AsSlice()),
		Port: int(id.LocalPort),
	}

	// Create outbound connection with socket protection DURING dial
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// CRITICAL: Protect socket BEFORE connect() is called
	if f.protectSocket != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				f.protectSocket(int(fd))
			})
		}
	}

	upstreamConn, err := dialer.DialContext(f.ctx, "tcp", dstAddr.String())
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstreamConn, tunConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(tunConn, upstreamConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done
}

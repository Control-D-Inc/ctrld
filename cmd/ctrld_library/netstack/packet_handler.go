package netstack

import (
	"fmt"
	"sync"
)

// PacketHandler defines the interface for reading and writing raw IP packets
// from/to the mobile TUN interface.
type PacketHandler interface {
	// ReadPacket reads a raw IP packet from the TUN interface.
	// This should be a blocking call.
	ReadPacket() ([]byte, error)

	// WritePacket writes a raw IP packet back to the TUN interface.
	WritePacket(packet []byte) error

	// Close closes the packet handler and releases resources.
	Close() error
}

// MobilePacketHandler implements PacketHandler using callbacks from mobile platforms.
// This bridges Go Mobile interface with the netstack implementation.
type MobilePacketHandler struct {
	readFunc  func() ([]byte, error)
	writeFunc func([]byte) error
	closeFunc func() error

	mu     sync.Mutex
	closed bool
}

// NewMobilePacketHandler creates a new packet handler with mobile callbacks.
func NewMobilePacketHandler(
	readFunc func() ([]byte, error),
	writeFunc func([]byte) error,
	closeFunc func() error,
) *MobilePacketHandler {
	return &MobilePacketHandler{
		readFunc:  readFunc,
		writeFunc: writeFunc,
		closeFunc: closeFunc,
		closed:    false,
	}
}

// ReadPacket reads a packet from mobile TUN interface.
func (m *MobilePacketHandler) ReadPacket() ([]byte, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()

	if closed {
		return nil, fmt.Errorf("packet handler is closed")
	}

	if m.readFunc == nil {
		return nil, fmt.Errorf("read function not set")
	}

	return m.readFunc()
}

// WritePacket writes a packet back to mobile TUN interface.
func (m *MobilePacketHandler) WritePacket(packet []byte) error {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()

	if closed {
		return fmt.Errorf("packet handler is closed")
	}

	if m.writeFunc == nil {
		return fmt.Errorf("write function not set")
	}

	return m.writeFunc(packet)
}

// Close closes the packet handler.
func (m *MobilePacketHandler) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	if m.closeFunc != nil {
		return m.closeFunc()
	}

	return nil
}

package netstack

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSBridge provides a bridge between the netstack DNS filter and the existing ctrld DNS proxy.
// It allows DNS queries captured from packets to be processed by the same logic as traditional DNS queries.
type DNSBridge struct {
	// Channel for sending DNS queries
	queryCh chan *DNSQuery

	// Channel for receiving DNS responses
	responseCh chan *DNSResponse

	// Map to track pending queries by transaction ID
	pendingQueries map[uint16]*PendingQuery
	mu             sync.RWMutex

	// Timeout for DNS queries
	queryTimeout time.Duration

	// Running state
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// DNSQuery represents a DNS query to be processed
type DNSQuery struct {
	ID      uint16      // Transaction ID for matching response
	Query   []byte      // Raw DNS query bytes
	RespCh  chan []byte // Response channel
	SrcIP   string      // Source IP for logging
	SrcPort uint16      // Source port
}

// DNSResponse represents a DNS response
type DNSResponse struct {
	ID       uint16
	Response []byte
}

// PendingQuery tracks a query waiting for response
type PendingQuery struct {
	Query     *DNSQuery
	Timestamp time.Time
}

// NewDNSBridge creates a new DNS bridge
func NewDNSBridge() *DNSBridge {
	return &DNSBridge{
		queryCh:        make(chan *DNSQuery, 100),
		responseCh:     make(chan *DNSResponse, 100),
		pendingQueries: make(map[uint16]*PendingQuery),
		queryTimeout:   5 * time.Second,
		stopCh:         make(chan struct{}),
	}
}

// Start starts the DNS bridge
func (b *DNSBridge) Start() {
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return
	}
	b.running = true
	b.mu.Unlock()

	// Start response handler
	b.wg.Add(1)
	go b.handleResponses()

	// Start timeout checker
	b.wg.Add(1)
	go b.checkTimeouts()
}

// Stop stops the DNS bridge
func (b *DNSBridge) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	b.running = false
	b.mu.Unlock()

	close(b.stopCh)
	b.wg.Wait()

	// Clean up pending queries
	b.mu.Lock()
	for _, pending := range b.pendingQueries {
		close(pending.Query.RespCh)
	}
	b.pendingQueries = make(map[uint16]*PendingQuery)
	b.mu.Unlock()
}

// ProcessQuery processes a DNS query and waits for response
func (b *DNSBridge) ProcessQuery(query []byte, srcIP string, srcPort uint16) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("invalid DNS query: too short")
	}

	// Parse DNS message to get transaction ID
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		return nil, fmt.Errorf("failed to parse DNS query: %v", err)
	}

	// Create response channel
	respCh := make(chan []byte, 1)

	// Create query
	dnsQuery := &DNSQuery{
		ID:      msg.Id,
		Query:   query,
		RespCh:  respCh,
		SrcIP:   srcIP,
		SrcPort: srcPort,
	}

	// Store as pending
	b.mu.Lock()
	b.pendingQueries[msg.Id] = &PendingQuery{
		Query:     dnsQuery,
		Timestamp: time.Now(),
	}
	b.mu.Unlock()

	// Send query
	select {
	case b.queryCh <- dnsQuery:
	case <-time.After(time.Second):
		b.mu.Lock()
		delete(b.pendingQueries, msg.Id)
		b.mu.Unlock()
		return nil, fmt.Errorf("query channel full")
	}

	// Wait for response with timeout
	select {
	case response := <-respCh:
		b.mu.Lock()
		delete(b.pendingQueries, msg.Id)
		b.mu.Unlock()
		return response, nil

	case <-time.After(b.queryTimeout):
		b.mu.Lock()
		delete(b.pendingQueries, msg.Id)
		b.mu.Unlock()
		return nil, fmt.Errorf("DNS query timeout")
	}
}

// GetQueryChannel returns the channel for receiving DNS queries
func (b *DNSBridge) GetQueryChannel() <-chan *DNSQuery {
	return b.queryCh
}

// SendResponse sends a DNS response back to the waiting query
func (b *DNSBridge) SendResponse(id uint16, response []byte) error {
	b.mu.RLock()
	pending, exists := b.pendingQueries[id]
	b.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no pending query for ID %d", id)
	}

	select {
	case pending.Query.RespCh <- response:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("failed to send response: channel blocked")
	}
}

// handleResponses handles incoming responses
func (b *DNSBridge) handleResponses() {
	defer b.wg.Done()

	for {
		select {
		case <-b.stopCh:
			return

		case resp := <-b.responseCh:
			if err := b.SendResponse(resp.ID, resp.Response); err != nil {
				// Log error but continue
			}
		}
	}
}

// checkTimeouts periodically checks for and removes timed out queries
func (b *DNSBridge) checkTimeouts() {
	defer b.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return

		case <-ticker.C:
			now := time.Now()
			b.mu.Lock()
			for id, pending := range b.pendingQueries {
				if now.Sub(pending.Timestamp) > b.queryTimeout {
					close(pending.Query.RespCh)
					delete(b.pendingQueries, id)
				}
			}
			b.mu.Unlock()
		}
	}
}

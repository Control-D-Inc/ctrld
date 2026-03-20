package netstack

import (
	"net"
	"sync"
	"time"
)

// IPTracker tracks IP addresses that have been resolved through DNS.
// This allows blocking direct IP connections that bypass DNS filtering.
type IPTracker struct {
	// Map of IP address string -> expiration time
	resolvedIPs map[string]time.Time
	mu          sync.RWMutex

	// TTL for tracked IPs (how long to remember them)
	ttl time.Duration

	// Running state
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewIPTracker creates a new IP tracker with the specified TTL
func NewIPTracker(ttl time.Duration) *IPTracker {
	if ttl == 0 {
		ttl = 5 * time.Minute // Default 5 minutes
	}

	return &IPTracker{
		resolvedIPs: make(map[string]time.Time),
		ttl:         ttl,
		stopCh:      make(chan struct{}),
	}
}

// Start starts the IP tracker cleanup routine
func (t *IPTracker) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.mu.Unlock()

	// Start cleanup goroutine to remove expired IPs
	t.wg.Add(1)
	go t.cleanupExpiredIPs()
}

// Stop stops the IP tracker
func (t *IPTracker) Stop() {
	if t == nil {
		return
	}

	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	t.running = false
	t.mu.Unlock()

	// Close stop channel (protected against double close)
	select {
	case <-t.stopCh:
		// Already closed
	default:
		close(t.stopCh)
	}

	t.wg.Wait()

	// Clear all tracked IPs
	t.mu.Lock()
	t.resolvedIPs = make(map[string]time.Time)
	t.mu.Unlock()
}

// TrackIP adds an IP address to the tracking list
func (t *IPTracker) TrackIP(ip net.IP) {
	if ip == nil {
		return
	}

	// Normalize to string format
	ipStr := ip.String()

	t.mu.Lock()
	t.resolvedIPs[ipStr] = time.Now().Add(t.ttl)
	t.mu.Unlock()
}

// IsTracked checks if an IP address is in the tracking list
// Optimized to minimize lock contention by avoiding write locks in the hot path
func (t *IPTracker) IsTracked(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ipStr := ip.String()

	t.mu.RLock()
	expiration, exists := t.resolvedIPs[ipStr]
	t.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if expired - but DON'T delete here to avoid write lock
	// Let the cleanup goroutine handle expired entries
	// This keeps IsTracked fast with only read locks
	return !time.Now().After(expiration)
}

// GetTrackedCount returns the number of currently tracked IPs
func (t *IPTracker) GetTrackedCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.resolvedIPs)
}

// cleanupExpiredIPs periodically removes expired IP entries
func (t *IPTracker) cleanupExpiredIPs() {
	defer t.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return

		case <-ticker.C:
			now := time.Now()
			t.mu.Lock()
			for ip, expiration := range t.resolvedIPs {
				if now.After(expiration) {
					delete(t.resolvedIPs, ip)
				}
			}
			t.mu.Unlock()
		}
	}
}

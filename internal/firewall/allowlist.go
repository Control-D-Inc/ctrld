// Package firewall provides DNS-resolved IP allowlist enforcement for ctrld's
// firewall mode. When enabled, only IPs that were successfully resolved by ctrld
// are allowed outbound connections — blocking hardcoded IPs, direct-IP fallbacks,
// and DNS bypass attempts.
//
// The AllowList is the core data structure: a concurrent map of allowed IPs
// populated by DNS responses, with TTL-based expiry and domain-level invalidation
// for live profile updates.
package firewall

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// AllowList tracks IPs that were resolved by ctrld and are allowed for outbound
// connections. It is safe for concurrent use from multiple goroutines.
//
// Architecture:
//   - ips: primary map, netip.Addr → *entry (expiry + originating domains)
//   - domains: reverse map, domain → []netip.Addr (for bulk invalidation on policy changes)
//   - permanent: IPs that are always allowed (loopback, RFC1918, upstream endpoints)
//
// The hot path is Contains(), which must be O(1) with zero allocations.
type AllowList struct {
	// ips is the primary allowlist. Keyed by IP address, value is the entry
	// containing expiry time and which domains resolved to this IP.
	ips sync.Map // netip.Addr → *entry

	// domains is the reverse map for bulk invalidation. When a domain's policy
	// changes (e.g., previously-allowed domain gets blocked), we can look up all
	// IPs associated with that domain and remove them.
	domains sync.Map // string → *domainEntry

	// permanent contains IPs that are always allowed regardless of DNS resolution.
	// These include loopback, RFC1918, link-local, ctrld listener IPs, and
	// upstream resolver IPs.
	permanent sync.Map // netip.Addr → struct{}

	// onChange is called (if non-nil) whenever the allowlist changes.
	// The callback receives the IP and whether it was added (true) or removed (false).
	// Platform-specific enforcement (pf/WFP) registers a callback here.
	onChange func(ip netip.Addr, added bool)

	// onBatchChange is called (if non-nil) with batches of changes.
	// When possible, AllowList prefers onBatchChange to reduce platform
	// enforcement calls. Single Add() calls still use onChange.
	onBatchChange func(added []netip.Addr, removed []netip.Addr)

	// mu protects mutations that need consistency across the ips/domains maps
	// and platform callbacks.
	mu sync.Mutex

	// stats tracks allowlist metrics without per-operation locks.
	totalAdds    atomic.Int64
	totalRemoves atomic.Int64
	totalHits    atomic.Int64
	totalMisses  atomic.Int64
}

// entry represents an allowed IP with expiry and provenance tracking.
// Fields are protected by mu since Add() and reap() may access concurrently.
type entry struct {
	mu      sync.Mutex
	expiry  time.Time
	domains []string // which domains resolved to this IP (for reverse lookup)
}

// domainEntry tracks all IPs associated with a domain for bulk invalidation.
type domainEntry struct {
	ips []netip.Addr
}

// Stats contains a snapshot of allowlist metrics.
type Stats struct {
	// AllowedIPs is the current number of IPs in the allowlist (non-permanent).
	AllowedIPs int `json:"allowed_ips"`
	// PermanentIPs is the number of permanently allowed IPs.
	PermanentIPs int `json:"permanent_ips"`
	// TrackedDomains is the number of domains with IP associations.
	TrackedDomains int `json:"tracked_domains"`
	// TotalAdds is the cumulative number of Add() calls.
	TotalAdds int64 `json:"total_adds"`
	// TotalRemoves is the cumulative number of Remove()/Flush() operations.
	TotalRemoves int64 `json:"total_removes"`
	// TotalHits is the number of Contains() calls that returned true.
	TotalHits int64 `json:"total_hits"`
	// TotalMisses is the number of Contains() calls that returned false.
	TotalMisses int64 `json:"total_misses"`
}

// New creates a new empty AllowList. Call AddPermanent() to seed it with
// IPs that should always be allowed (loopback, upstreams, etc.), then
// StartReaper() to begin background TTL expiry.
func New() *AllowList {
	return &AllowList{}
}

// SetOnChange registers a callback that fires on each individual IP change.
// Use SetOnBatchChange instead for platform enforcement (reduces churn).
func (a *AllowList) SetOnChange(fn func(ip netip.Addr, added bool)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onChange = fn
}

// SetOnBatchChange registers a callback that fires with batched changes.
// The reaper and FlushDomain operations use this to deliver bulk updates.
func (a *AllowList) SetOnBatchChange(fn func(added []netip.Addr, removed []netip.Addr)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onBatchChange = fn
}

// Add inserts an IP into the allowlist with a TTL and domain association.
// If the IP already exists, its expiry is extended (max of old and new) and the
// domain is added to its provenance list. This is called from the DNS proxy
// response path for every A/AAAA record in a successful resolution.
//
// The domain parameter tracks which DNS query produced this IP, enabling
// FlushDomain() to invalidate IPs when a domain's policy changes.
func (a *AllowList) Add(ip netip.Addr, domain string, ttl time.Duration) {
	if !ip.IsValid() {
		return
	}

	// Normalize IPv4-in-IPv6 to plain IPv4 for consistent lookups.
	ip = ip.Unmap()

	expiry := time.Now().Add(ttl)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Update or create the IP entry. LoadOrStore avoids overwriting an entry if
	// another goroutine won the initialization race. The outer mutex keeps the
	// IP and domain reverse maps in step with Flush/FlushDomain callbacks.
	entryValue, loaded := a.ips.LoadOrStore(ip, &entry{
		expiry:  expiry,
		domains: []string{domain},
	})
	if loaded {
		e := entryValue.(*entry)
		e.mu.Lock()
		// Extend expiry if the new one is later.
		if expiry.After(e.expiry) {
			e.expiry = expiry
		}
		// Add domain to provenance if not already tracked.
		if !containsString(e.domains, domain) {
			e.domains = append(e.domains, domain)
		}
		e.mu.Unlock()
	} else {
		a.totalAdds.Add(1)

		// Notify platform enforcement of the new IP.
		if a.onChange != nil {
			a.onChange(ip, true)
		}
	}

	// Update the domain → IP reverse map.
	de, _ := a.domains.LoadOrStore(domain, &domainEntry{})
	d := de.(*domainEntry)
	if !containsAddr(d.ips, ip) {
		d.ips = append(d.ips, ip)
	}
}

// Contains checks whether an IP is allowed. This is the hot path — called
// per-packet on mobile (via netstack) and per-connection on desktop (via
// pf/WFP). It must be O(1) with zero allocations.
//
// Returns true if the IP is in the allowlist (not expired) or in the
// permanent list.
func (a *AllowList) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	ip = ip.Unmap()

	// Check permanent list first (most common for loopback/private).
	if a.containsPermanent(ip) {
		a.totalHits.Add(1)
		return true
	}

	// Check dynamic allowlist.
	if existing, ok := a.ips.Load(ip); ok {
		e := existing.(*entry)
		e.mu.Lock()
		expired := time.Now().After(e.expiry)
		e.mu.Unlock()
		if !expired {
			a.totalHits.Add(1)
			return true
		}
		// Expired — will be cleaned up by reaper. Don't remove here to avoid
		// per-lookup overhead and lock contention.
	}

	a.totalMisses.Add(1)
	return false
}

// Remove deletes a single IP from the allowlist. Does not affect permanent entries.
func (a *AllowList) Remove(ip netip.Addr) {
	ip = ip.Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()

	if existing, ok := a.ips.LoadAndDelete(ip); ok {
		e := existing.(*entry)
		a.totalRemoves.Add(1)

		e.mu.Lock()
		domains := append([]string(nil), e.domains...)
		e.mu.Unlock()

		// Clean up domain reverse map entries.
		for _, domain := range domains {
			a.removeDomainIP(domain, ip)
		}

		if a.onChange != nil {
			a.onChange(ip, false)
		}
	}
}

// FlushDomain removes all IPs associated with a specific domain. This is used
// when a profile/policy change makes a previously-allowed domain blocked.
// IPs that are also associated with OTHER still-allowed domains are kept.
func (a *AllowList) FlushDomain(domain string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	de, ok := a.domains.LoadAndDelete(domain)
	if !ok {
		return
	}
	d := de.(*domainEntry)
	ipsToCheck := make([]netip.Addr, len(d.ips))
	copy(ipsToCheck, d.ips)

	var removed []netip.Addr

	for _, ip := range ipsToCheck {
		existing, ok := a.ips.Load(ip)
		if !ok {
			continue
		}
		e := existing.(*entry)

		e.mu.Lock()
		// Remove this domain from the entry's domain list.
		e.domains = removeString(e.domains, domain)
		empty := len(e.domains) == 0
		e.mu.Unlock()

		// If no other domains reference this IP, remove it entirely.
		if empty {
			a.ips.Delete(ip)
			a.totalRemoves.Add(1)
			removed = append(removed, ip)
		}
	}

	// Batch notify platform enforcement.
	if len(removed) > 0 && a.onBatchChange != nil {
		a.onBatchChange(nil, removed)
	} else if a.onChange != nil {
		for _, ip := range removed {
			a.onChange(ip, false)
		}
	}
}

// Flush removes all non-permanent entries. Used on network state changes
// (WiFi→cellular, interface IP changes) where stale IPs from the old network
// may no longer be valid. DNS cache should also be flushed so that subsequent
// queries repopulate both caches.
func (a *AllowList) Flush() {
	a.mu.Lock()
	defer a.mu.Unlock()

	var removed []netip.Addr

	a.ips.Range(func(key, value any) bool {
		ip := key.(netip.Addr)
		a.ips.Delete(ip)
		a.totalRemoves.Add(1)
		removed = append(removed, ip)
		return true
	})

	// Clear all domain reverse mappings.
	a.domains.Range(func(key, _ any) bool {
		a.domains.Delete(key)
		return true
	})

	// Batch notify platform enforcement.
	if len(removed) > 0 && a.onBatchChange != nil {
		a.onBatchChange(nil, removed)
	} else if a.onChange != nil {
		for _, ip := range removed {
			a.onChange(ip, false)
		}
	}
}

// AddPermanent adds an IP to the permanent allowlist. Permanent entries never
// expire and survive Flush(). Use for:
//   - Loopback (127.0.0.0/8, ::1)
//   - RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Link-local (169.254.0.0/16, fe80::/10)
//   - ctrld listener IPs
//   - DoH/DoT/DoQ upstream IPs
//   - ControlD API endpoint IPs
func (a *AllowList) AddPermanent(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	ip = ip.Unmap()
	a.permanent.Store(ip, struct{}{})
}

// AddPermanentPrefix adds an entire CIDR prefix to the permanent allowlist.
// Used for ranges like 127.0.0.0/8, 10.0.0.0/8, etc.
// For large prefixes (e.g., /8), this stores the prefix for range-based lookup
// rather than enumerating all IPs.
func (a *AllowList) AddPermanentPrefix(prefix netip.Prefix) {
	// For small prefixes, enumerate. For large ones, we'd need a different approach.
	// Since we're dealing with a known set of well-defined ranges, and Contains()
	// needs to be fast, we check prefixes in a separate path.
	// Store the prefix in a separate list for range-based checks.
	a.permanent.Store(prefix, struct{}{})
}

// containsPermanent checks both individual IPs and prefix ranges in the permanent list.
func (a *AllowList) containsPermanent(ip netip.Addr) bool {
	// Direct IP match.
	if _, ok := a.permanent.Load(ip); ok {
		return true
	}

	// Check prefix ranges. We iterate the permanent map looking for Prefix entries.
	// This is acceptable because the permanent map is small and rarely changes.
	found := false
	a.permanent.Range(func(key, _ any) bool {
		if prefix, ok := key.(netip.Prefix); ok {
			if prefix.Contains(ip) {
				found = true
				return false // stop iteration
			}
		}
		return true
	})
	return found
}

// PermanentEntries returns snapshots of permanently allowed individual IPs and
// prefixes. Platform enforcers use this to mirror the in-memory permanent
// allowlist into kernel-level permit rules.
func (a *AllowList) PermanentEntries() ([]netip.Addr, []netip.Prefix) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var addrs []netip.Addr
	var prefixes []netip.Prefix
	a.permanent.Range(func(key, _ any) bool {
		switch v := key.(type) {
		case netip.Addr:
			addrs = append(addrs, v)
		case netip.Prefix:
			prefixes = append(prefixes, v)
		}
		return true
	})
	return addrs, prefixes
}

// RemovePermanent removes an IP from the permanent allowlist.
func (a *AllowList) RemovePermanent(ip netip.Addr) {
	ip = ip.Unmap()
	a.permanent.Delete(ip)
}

// Stats returns a snapshot of current allowlist metrics.
func (a *AllowList) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	var s Stats
	now := time.Now()
	a.ips.Range(func(_, value any) bool {
		e := value.(*entry)
		e.mu.Lock()
		expired := now.After(e.expiry)
		e.mu.Unlock()
		if !expired {
			s.AllowedIPs++
		}
		return true
	})
	a.permanent.Range(func(_, _ any) bool {
		s.PermanentIPs++
		return true
	})
	a.domains.Range(func(_, _ any) bool {
		s.TrackedDomains++
		return true
	})
	s.TotalAdds = a.totalAdds.Load()
	s.TotalRemoves = a.totalRemoves.Load()
	s.TotalHits = a.totalHits.Load()
	s.TotalMisses = a.totalMisses.Load()
	return s
}

// StartReaper begins a background goroutine that periodically removes expired
// entries from the allowlist. It runs every 30 seconds and batches removals
// for efficient platform enforcement notification.
//
// The reaper is intentionally separate from Contains() to avoid per-lookup
// overhead. Expired entries may linger for up to 30 seconds, which is acceptable
// since DNS TTLs are typically 30s-300s and the reaper interval is a fraction of that.
func (a *AllowList) StartReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.reap()
			}
		}
	}()
}

// reap removes expired entries and notifies platform enforcement.
func (a *AllowList) reap() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	var removed []netip.Addr

	a.ips.Range(func(key, value any) bool {
		ip := key.(netip.Addr)
		e := value.(*entry)

		e.mu.Lock()
		expired := now.After(e.expiry)
		var domains []string
		if expired {
			domains = make([]string, len(e.domains))
			copy(domains, e.domains)
		}
		e.mu.Unlock()

		if expired {
			a.ips.Delete(ip)
			a.totalRemoves.Add(1)
			removed = append(removed, ip)

			// Clean up domain reverse map.
			for _, domain := range domains {
				a.removeDomainIP(domain, ip)
			}
		}
		return true
	})

	if len(removed) > 0 && a.onBatchChange != nil {
		a.onBatchChange(nil, removed)
	} else if a.onChange != nil {
		for _, ip := range removed {
			a.onChange(ip, false)
		}
	}
}

// removeDomainIP removes an IP from a domain's reverse map entry.
func (a *AllowList) removeDomainIP(domain string, ip netip.Addr) {
	de, ok := a.domains.Load(domain)
	if !ok {
		return
	}
	d := de.(*domainEntry)
	d.ips = removeAddr(d.ips, ip)
	empty := len(d.ips) == 0

	// Clean up empty domain entries.
	if empty {
		a.domains.Delete(domain)
	}
}

// AllowedIPs returns a snapshot of all currently allowed (non-expired, non-permanent) IPs.
// Used by platform enforcement for initial table population.
func (a *AllowList) AllowedIPs() []netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	var ips []netip.Addr
	a.ips.Range(func(key, value any) bool {
		ip := key.(netip.Addr)
		e := value.(*entry)
		e.mu.Lock()
		expiry := e.expiry
		e.mu.Unlock()
		if now.Before(expiry) {
			ips = append(ips, ip)
		}
		return true
	})
	return ips
}

// --- Helpers ---

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(ss []string, s string) []string {
	for i, v := range ss {
		if v == s {
			return append(ss[:i], ss[i+1:]...)
		}
	}
	return ss
}

func containsAddr(addrs []netip.Addr, addr netip.Addr) bool {
	for _, a := range addrs {
		if a == addr {
			return true
		}
	}
	return false
}

func removeAddr(addrs []netip.Addr, addr netip.Addr) []netip.Addr {
	for i, a := range addrs {
		if a == addr {
			return append(addrs[:i], addrs[i+1:]...)
		}
	}
	return addrs
}

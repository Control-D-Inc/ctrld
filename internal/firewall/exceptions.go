package firewall

import (
	"net/netip"
	"sort"
)

// Exception handling: the organization's Allowed Destination IP list.
//
// Firewall Mode only permits what ctrld itself resolved, which makes a service
// addressed by literal IP — with no DNS lookup to observe — unreachable. An
// organization can therefore publish a list of destinations that stay reachable
// regardless; the API delivers the effective list (own entries plus any inherited
// from a parent organization) with every configuration refresh.
//
// The list is applied as a *set*, not as individual additions: each refresh
// replaces the previous snapshot, so an entry removed upstream stops bypassing
// Firewall Mode as soon as the refresh lands. Entries never expire in between —
// unlike DNS-resolved IPs they carry no TTL.
//
// This type holds the *desired* set only. Mirroring it into pf/WFP can fail, so
// what platform enforcement has actually accepted is tracked by the caller (see
// prog.reconcileAllowedDestinations), which retries until the two agree. Storing
// "applied" here would make a failed pfctl call look like a success to every
// later refresh.
//
// The same split matters to anything embedding this package: Contains() answers
// from the set the last SetExceptions call installed, which is what ctrld wants
// enforced, not what the kernel is enforcing. On macOS and Windows the platform
// state is the gate and the difference is tracked and retried, so a mirror that
// failed cannot let traffic through. An embedder that gates on Contains() alone
// has no such gate, and inherits the desired set the moment it is set.

// SetExceptions replaces the allowed-destination set with prefixes. Entries are
// masked and de-duplicated first, so equivalent spellings of the same network
// (e.g. "10.1.2.3/24" and "10.1.2.0/24") do not rebuild the index.
//
// Deliberately reports nothing about whether the set changed. "Nothing changed"
// is not a licence to skip the platform reconcile: enforcement can be behind the
// desired set from an earlier failed mirror, and that retry is driven by
// comparing against what the platform accepted, not against the previous desired
// set. A caller that skipped on "unchanged" would strand exactly the case the
// retry exists for.
func (a *AllowList) SetExceptions(prefixes []netip.Prefix) {
	next := normalizeExceptions(prefixes)

	// Serialized so two concurrent refreshes cannot interleave their compare and
	// store steps and leave the older set installed.
	a.exceptionsMu.Lock()
	defer a.exceptionsMu.Unlock()

	if samePrefixes(a.exceptionsSnapshot(), next) {
		return
	}
	a.exceptions.Store(newExceptionIndex(next))
}

// Exceptions returns the current allowed-destination set, ordered and masked.
// The result must not be modified — it is the live snapshot shared with the
// Contains() hot path.
func (a *AllowList) Exceptions() []netip.Prefix {
	return a.exceptionsSnapshot()
}

// exceptionsSnapshot returns the stored set, or nil when none was ever applied.
func (a *AllowList) exceptionsSnapshot() []netip.Prefix {
	if idx := a.exceptions.Load(); idx != nil {
		return idx.prefixes
	}
	return nil
}

// containsException reports whether ip falls inside an allowed destination.
//
// Binary search over sorted, merged address ranges: Contains() is the
// per-connection (and, for embedders, per-packet) hot path, and an organization
// list can hold thousands of prefixes, so a linear scan would put its length on
// that path. An empty set — the overwhelmingly common case — costs one nil check.
func (a *AllowList) containsException(ip netip.Addr) bool {
	idx := a.exceptions.Load()
	if idx == nil {
		return false
	}
	ranges := idx.v6
	if ip.Is4() {
		ranges = idx.v4
	}
	if len(ranges) == 0 {
		return false
	}
	// Find the last range whose start is <= ip; it is the only one that can
	// contain ip, because ranges are sorted and non-overlapping.
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].lo.Compare(ip) > 0 })
	if i == 0 {
		return false
	}
	return ranges[i-1].hi.Compare(ip) >= 0
}

// exceptionIndex is an immutable lookup structure over one allowed-destination
// set: the normalized prefixes as applied, plus per-family sorted address ranges
// for lookups. Published as a whole behind an atomic pointer, so a refresh never
// exposes a half-rebuilt index to a concurrent Contains().
type exceptionIndex struct {
	prefixes []netip.Prefix
	v4       []addrRange
	v6       []addrRange
}

// addrRange is an inclusive address range, the range form of one prefix (or of
// several that were merged because they overlap or abut).
type addrRange struct {
	lo, hi netip.Addr
}

// newExceptionIndex builds the lookup index for a normalized prefix set.
func newExceptionIndex(prefixes []netip.Prefix) *exceptionIndex {
	idx := &exceptionIndex{prefixes: prefixes}
	for _, prefix := range prefixes {
		r := addrRange{lo: prefix.Addr(), hi: lastAddr(prefix)}
		if prefix.Addr().Is4() {
			idx.v4 = append(idx.v4, r)
		} else {
			idx.v6 = append(idx.v6, r)
		}
	}
	idx.v4 = sortAndMerge(idx.v4)
	idx.v6 = sortAndMerge(idx.v6)
	return idx
}

// lastAddr returns the highest address in a masked prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		b := prefix.Addr().As4()
		for i := prefix.Bits(); i < 32; i++ {
			b[i/8] |= 1 << (7 - i%8)
		}
		return netip.AddrFrom4(b)
	}
	b := prefix.Addr().As16()
	for i := prefix.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom16(b)
}

// sortAndMerge orders ranges by start address and coalesces the ones that
// overlap or abut, so the search invariant (sorted, non-overlapping) holds even
// when an organization lists a network and an address inside it.
func sortAndMerge(ranges []addrRange) []addrRange {
	if len(ranges) < 2 {
		return ranges
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo.Compare(ranges[j].lo) < 0 })

	out := ranges[:1]
	for _, r := range ranges[1:] {
		last := &out[len(out)-1]
		// Abutting counts as overlapping: last.hi.Next() == r.lo means the two
		// ranges are contiguous with no gap to preserve.
		if r.lo.Compare(last.hi) <= 0 || r.lo == last.hi.Next() {
			if r.hi.Compare(last.hi) > 0 {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// normalizeExceptions masks, de-duplicates and orders prefixes so that two sets
// with the same meaning compare equal, and so logged deltas are stable.
func normalizeExceptions(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		masked := prefix.Masked()
		if _, dup := seen[masked]; dup {
			continue
		}
		seen[masked] = struct{}{}
		out = append(out, masked)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// samePrefixes reports whether two normalized sets are identical.
func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

package firewall

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestSetExceptionsNormalizesAndReplaces(t *testing.T) {
	al := New()

	al.SetExceptions(prefixes(t, "203.0.113.10/32", "198.51.100.0/24"))
	first := al.Exceptions()
	if got := prefixStrings(first); len(got) != 2 {
		t.Fatalf("Exceptions() = %v, want 2 entries", got)
	}

	// Same set, different order and an unmasked spelling of the same network. The
	// index must not be rebuilt: the list is re-applied on every configuration
	// refresh, and a rebuild would republish it to the Contains() hot path hourly
	// for a set that did not change.
	al.SetExceptions(prefixes(t, "198.51.100.77/24", "203.0.113.10/32"))
	same := al.Exceptions()
	if len(same) != len(first) || &same[0] != &first[0] {
		t.Fatalf("an equivalent set replaced the index: %v -> %v", prefixStrings(first), prefixStrings(same))
	}

	al.SetExceptions(prefixes(t, "203.0.113.10/32", "2001:db8::/48"))
	changed := al.Exceptions()
	if got := prefixStrings(changed); len(got) != 2 {
		t.Fatalf("Exceptions() = %v, want 2 entries", got)
	}
	if &changed[0] == &first[0] {
		t.Fatal("a changed set left the previous index installed")
	}

	// An empty list clears the set: an organization can withdraw everything.
	al.SetExceptions(nil)
	if got := al.Exceptions(); len(got) != 0 {
		t.Fatalf("Exceptions() after clear = %v, want empty", got)
	}
	al.SetExceptions(nil)
	if got := al.Exceptions(); len(got) != 0 {
		t.Fatalf("Exceptions() after clearing twice = %v, want empty", got)
	}
}

func TestExceptionsAllowWithoutDNS(t *testing.T) {
	al := New()
	inRange := netip.MustParseAddr("198.51.100.7")
	host := netip.MustParseAddr("203.0.113.10")
	other := netip.MustParseAddr("203.0.113.11")
	v6 := netip.MustParseAddr("2001:db8::1")

	for _, ip := range []netip.Addr{inRange, host, other, v6} {
		if al.Contains(ip) {
			t.Fatalf("%s allowed before any exception was applied", ip)
		}
	}

	al.SetExceptions(prefixes(t, "198.51.100.0/24", "203.0.113.10/32", "2001:db8::/48"))

	// Allowed with no prior DNS resolution — the point of the list.
	for _, ip := range []netip.Addr{inRange, host, v6} {
		if !al.Contains(ip) {
			t.Fatalf("%s not allowed by the exception set", ip)
		}
	}
	// An unresolved public destination outside the set stays blocked.
	if al.Contains(other) {
		t.Fatalf("%s allowed although it is outside the exception set", other)
	}

	// Removing an entry stops it bypassing, and leaves the rest allowed.
	al.SetExceptions(prefixes(t, "203.0.113.10/32"))
	if al.Contains(inRange) {
		t.Fatalf("%s still allowed after its prefix was removed", inRange)
	}
	if !al.Contains(host) {
		t.Fatalf("%s should still be allowed", host)
	}
}

// TestExceptionsBoundaries pins the range arithmetic the binary-search index
// rests on: the first and last address of a prefix are inside it, the addresses
// on either side are not, and a family never matches the other family's ranges.
func TestExceptionsBoundaries(t *testing.T) {
	al := New()
	al.SetExceptions(prefixes(t, "198.51.100.0/24", "2001:db8:1::/48"))

	in := []string{
		"198.51.100.0", "198.51.100.255",
		"2001:db8:1::", "2001:db8:1:ffff:ffff:ffff:ffff:ffff",
	}
	out := []string{
		"198.51.99.255", "198.51.101.0",
		"2001:db8:0:ffff:ffff:ffff:ffff:ffff", "2001:db8:2::",
	}
	for _, s := range in {
		if !al.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be inside the exception set", s)
		}
	}
	for _, s := range out {
		if al.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be outside the exception set", s)
		}
	}
}

// TestExceptionsOverlappingEntries covers an organization listing a network and
// an address within it, plus two adjacent networks - both of which the index
// merges, and neither of which may change what is allowed.
func TestExceptionsOverlappingEntries(t *testing.T) {
	al := New()
	al.SetExceptions(prefixes(t,
		"198.51.100.0/24", "198.51.100.7/32", // contained
		"203.0.113.0/25", "203.0.113.128/25", // adjacent halves
	))

	for _, s := range []string{"198.51.100.7", "198.51.100.200", "203.0.113.1", "203.0.113.200"} {
		if !al.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	for _, s := range []string{"198.51.101.7", "203.0.114.1"} {
		if al.Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be allowed", s)
		}
	}
}

func TestExceptionsIndependentOfDNSAllowlist(t *testing.T) {
	al := New()
	al.SetExceptions(prefixes(t, "203.0.113.0/24"))

	resolved := netip.MustParseAddr("192.0.2.5")
	al.Add(resolved, "example.com", time.Minute)

	// Flush discards DNS-resolved IPs; exceptions are administrative and survive.
	al.Flush()
	if al.Contains(resolved) {
		t.Fatalf("%s survived a flush", resolved)
	}
	if !al.Contains(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("exception did not survive a flush of the DNS-resolved allowlist")
	}

	// A removed exception is not resurrected by an unrelated DNS resolution.
	al.SetExceptions(nil)
	if al.Contains(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("cleared exception still allowed")
	}
}

func TestExceptionsInStats(t *testing.T) {
	al := New()
	if got := al.Stats().ExceptionPrefixes; got != 0 {
		t.Fatalf("ExceptionPrefixes = %d, want 0", got)
	}
	al.SetExceptions(prefixes(t, "203.0.113.0/24", "2001:db8::/48"))
	if got := al.Stats().ExceptionPrefixes; got != 2 {
		t.Fatalf("ExceptionPrefixes = %d, want 2", got)
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

// benchExceptions builds a set of n distinct /24s plus one /32 the benchmark
// looks up, so lookups traverse the whole index rather than hitting an early
// entry.
func benchExceptions(n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)))
	}
	return out
}

// BenchmarkContainsWithExceptions guards the hot path: Contains() is called per
// connection (per packet for embedders), so the cost of a large organization
// list must not scale with its length.
func BenchmarkContainsWithExceptions(b *testing.B) {
	for _, n := range []int{0, 100, 2000} {
		b.Run(fmt.Sprintf("prefixes=%d", n), func(b *testing.B) {
			al := New()
			if n > 0 {
				al.SetExceptions(benchExceptions(n))
			}
			ip := netip.MustParseAddr("203.0.113.10") // never in the set: worst case
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				al.Contains(ip)
			}
		})
	}
}

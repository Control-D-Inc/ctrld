package firewall

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestAddAndContains(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")

	// IP should not be allowed before adding.
	if al.Contains(ip) {
		t.Fatal("expected IP to not be in allowlist before Add")
	}

	al.Add(ip, "example.com", 5*time.Minute)

	if !al.Contains(ip) {
		t.Fatal("expected IP to be in allowlist after Add")
	}
}

func TestContainsExpired(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")

	// Add with a TTL that's already past.
	al.Add(ip, "example.com", -1*time.Second)

	if al.Contains(ip) {
		t.Fatal("expected expired IP to not be allowed")
	}
}

func TestAddExtendsExpiry(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")

	// Add with short TTL.
	al.Add(ip, "example.com", 1*time.Second)
	// Extend with longer TTL.
	al.Add(ip, "cdn.example.com", 1*time.Hour)

	// Should still be valid.
	if !al.Contains(ip) {
		t.Fatal("expected IP to be allowed after expiry extension")
	}

	// Check domain provenance was tracked.
	existing, ok := al.ips.Load(ip)
	if !ok {
		t.Fatal("expected IP entry to exist")
	}
	e := existing.(*entry)
	e.mu.Lock()
	domainCount := len(e.domains)
	e.mu.Unlock()
	if domainCount != 2 {
		t.Fatalf("expected 2 domains, got %d", domainCount)
	}
}

func TestRemove(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")

	al.Add(ip, "example.com", 5*time.Minute)
	al.Remove(ip)

	if al.Contains(ip) {
		t.Fatal("expected IP to not be in allowlist after Remove")
	}
}

func TestPermanent(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("127.0.0.1")

	al.AddPermanent(ip)

	if !al.Contains(ip) {
		t.Fatal("expected permanent IP to be allowed")
	}

	// Permanent entries survive Flush.
	al.Flush()

	if !al.Contains(ip) {
		t.Fatal("expected permanent IP to survive Flush")
	}
}

func TestPermanentPrefix(t *testing.T) {
	al := New()
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	al.AddPermanentPrefix(prefix)

	if !al.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected IP in permanent prefix to be allowed")
	}
	if !al.Contains(netip.MustParseAddr("10.255.255.255")) {
		t.Fatal("expected IP at end of permanent prefix to be allowed")
	}
	if al.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Fatal("expected IP outside permanent prefix to not be allowed")
	}
}

func TestFlush(t *testing.T) {
	al := New()
	al.AddPermanent(netip.MustParseAddr("127.0.0.1"))
	al.Add(netip.MustParseAddr("93.184.216.34"), "example.com", 5*time.Minute)
	al.Add(netip.MustParseAddr("151.101.1.69"), "reddit.com", 5*time.Minute)

	al.Flush()

	// Dynamic entries should be gone.
	if al.Contains(netip.MustParseAddr("93.184.216.34")) {
		t.Fatal("expected dynamic IP to be removed after Flush")
	}
	if al.Contains(netip.MustParseAddr("151.101.1.69")) {
		t.Fatal("expected dynamic IP to be removed after Flush")
	}

	// Permanent should survive.
	if !al.Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("expected permanent IP to survive Flush")
	}

	// Domain reverse map should be cleared.
	stats := al.Stats()
	if stats.TrackedDomains != 0 {
		t.Fatalf("expected 0 tracked domains after Flush, got %d", stats.TrackedDomains)
	}
}

func TestFlushDomain(t *testing.T) {
	al := New()

	// IP shared between two domains.
	sharedIP := netip.MustParseAddr("93.184.216.34")
	exclusiveIP := netip.MustParseAddr("93.184.216.35")

	al.Add(sharedIP, "example.com", 5*time.Minute)
	al.Add(sharedIP, "cdn.example.com", 5*time.Minute)
	al.Add(exclusiveIP, "example.com", 5*time.Minute)

	// Flush only example.com.
	al.FlushDomain("example.com")

	// Shared IP should remain because cdn.example.com still references it.
	if !al.Contains(sharedIP) {
		t.Fatal("expected shared IP to remain (still referenced by cdn.example.com)")
	}

	// Exclusive IP should be removed (only referenced by example.com).
	if al.Contains(exclusiveIP) {
		t.Fatal("expected exclusive IP to be removed after FlushDomain")
	}
}

func TestFlushFallsBackToOnChange(t *testing.T) {
	al := New()
	ip1 := netip.MustParseAddr("93.184.216.34")
	ip2 := netip.MustParseAddr("151.101.1.69")

	var removed []netip.Addr
	al.SetOnChange(func(ip netip.Addr, added bool) {
		if !added {
			removed = append(removed, ip)
		}
	})

	al.Add(ip1, "example.com", 5*time.Minute)
	al.Add(ip2, "reddit.com", 5*time.Minute)
	al.Flush()

	if len(removed) != 2 {
		t.Fatalf("expected 2 removed IP callbacks, got %d", len(removed))
	}
}

func TestFlushDomainThenAddKeepsPlatformInSync(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")
	platform := make(map[netip.Addr]bool)

	al.SetOnChange(func(ip netip.Addr, added bool) {
		platform[ip] = added
	})
	al.SetOnBatchChange(func(added, removed []netip.Addr) {
		for _, ip := range added {
			platform[ip] = true
		}
		for _, ip := range removed {
			platform[ip] = false
		}
	})

	al.Add(ip, "example.com", 5*time.Minute)
	al.FlushDomain("example.com")
	al.Add(ip, "example.com", 5*time.Minute)

	if !al.Contains(ip) {
		t.Fatal("expected IP to be allowed after re-add")
	}
	if !platform[ip] {
		t.Fatal("expected platform callback state to match allowlist after flush/re-add")
	}
}

func TestConcurrentAddFlushDomainAndReap(t *testing.T) {
	al := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	al.StartReaper(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ip := netip.AddrFrom4([4]byte{10, byte(n), byte(j / 255), byte(j % 255)})
				al.Add(ip, "example.com", time.Minute)
				al.Contains(ip)
			}
		}(i)
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				al.FlushDomain("example.com")
				al.reap()
			}
		}()
	}

	wg.Wait()
}

func TestIPv4MappedIPv6(t *testing.T) {
	al := New()

	// Add as IPv4.
	al.Add(netip.MustParseAddr("93.184.216.34"), "example.com", 5*time.Minute)

	// Look up as IPv4-mapped IPv6 — should still match due to Unmap().
	mapped := netip.AddrFrom16(netip.MustParseAddr("93.184.216.34").As16())
	if !al.Contains(mapped) {
		t.Fatal("expected IPv4-mapped IPv6 lookup to match IPv4 entry")
	}
}

func TestIPv6(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")

	al.Add(ip, "example.com", 5*time.Minute)

	if !al.Contains(ip) {
		t.Fatal("expected IPv6 address to be in allowlist")
	}
}

func TestReaper(t *testing.T) {
	al := New()
	ip := netip.MustParseAddr("93.184.216.34")

	// Add with very short TTL that's already expired.
	al.Add(ip, "example.com", -1*time.Second)

	// Manually trigger reaper.
	al.reap()

	// Should have been cleaned up.
	_, ok := al.ips.Load(ip)
	if ok {
		t.Fatal("expected reaper to remove expired entry from ips map")
	}
}

func TestReaperFallsBackToOnChange(t *testing.T) {
	al := New()

	var removed []netip.Addr
	al.SetOnChange(func(ip netip.Addr, added bool) {
		if !added {
			removed = append(removed, ip)
		}
	})

	al.Add(netip.MustParseAddr("1.1.1.1"), "one.com", -1*time.Second)
	al.Add(netip.MustParseAddr("2.2.2.2"), "two.com", -1*time.Second)
	al.reap()

	if len(removed) != 2 {
		t.Fatalf("expected 2 removed IP callbacks, got %d", len(removed))
	}
}

func TestReaperBatchCallback(t *testing.T) {
	al := New()

	var removedIPs []netip.Addr
	al.SetOnBatchChange(func(added, removed []netip.Addr) {
		removedIPs = append(removedIPs, removed...)
	})

	al.Add(netip.MustParseAddr("1.1.1.1"), "one.com", -1*time.Second)
	al.Add(netip.MustParseAddr("2.2.2.2"), "two.com", -1*time.Second)
	al.Add(netip.MustParseAddr("3.3.3.3"), "three.com", 1*time.Hour) // not expired

	al.reap()

	if len(removedIPs) != 2 {
		t.Fatalf("expected 2 removed IPs in batch callback, got %d", len(removedIPs))
	}
}

func TestStatsExcludesExpiredAllowedIPs(t *testing.T) {
	al := New()

	al.Add(netip.MustParseAddr("93.184.216.34"), "example.com", -1*time.Second)
	al.Add(netip.MustParseAddr("151.101.1.69"), "reddit.com", 5*time.Minute)

	stats := al.Stats()
	if stats.AllowedIPs != 1 {
		t.Fatalf("expected 1 non-expired allowed IP, got %d", stats.AllowedIPs)
	}
}

func TestStats(t *testing.T) {
	al := New()

	al.AddPermanent(netip.MustParseAddr("127.0.0.1"))
	al.AddPermanentPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	al.Add(netip.MustParseAddr("93.184.216.34"), "example.com", 5*time.Minute)
	al.Add(netip.MustParseAddr("151.101.1.69"), "reddit.com", 5*time.Minute)

	// Generate some hits/misses.
	al.Contains(netip.MustParseAddr("93.184.216.34")) // hit
	al.Contains(netip.MustParseAddr("127.0.0.1"))     // hit (permanent)
	al.Contains(netip.MustParseAddr("8.8.8.8"))       // miss

	stats := al.Stats()

	if stats.AllowedIPs != 2 {
		t.Fatalf("expected 2 allowed IPs, got %d", stats.AllowedIPs)
	}
	// Permanent count includes both the individual IP and the prefix.
	if stats.PermanentIPs != 2 {
		t.Fatalf("expected 2 permanent entries, got %d", stats.PermanentIPs)
	}
	if stats.TrackedDomains != 2 {
		t.Fatalf("expected 2 tracked domains, got %d", stats.TrackedDomains)
	}
	if stats.TotalHits != 2 {
		t.Fatalf("expected 2 total hits, got %d", stats.TotalHits)
	}
	if stats.TotalMisses != 1 {
		t.Fatalf("expected 1 total miss, got %d", stats.TotalMisses)
	}
}

func TestConcurrentAccess(t *testing.T) {
	al := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	al.StartReaper(ctx)
	al.AddPermanent(netip.MustParseAddr("127.0.0.1"))

	var wg sync.WaitGroup
	// Concurrent writers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ip := netip.AddrFrom4([4]byte{10, 0, byte(n), byte(j)})
				al.Add(ip, "test.com", 1*time.Minute)
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ip := netip.AddrFrom4([4]byte{10, 0, byte(n), byte(j)})
				al.Contains(ip)
			}
		}(i)
	}

	// Concurrent flush.
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		al.Flush()
	}()

	wg.Wait()
}

func TestStartReaperWithContext(t *testing.T) {
	// This test verifies the reaper goroutine starts and stops cleanly.
	// We test actual reaping behavior via TestReaper (calls reap() directly).
	al := New()
	ctx, cancel := context.WithCancel(context.Background())
	al.StartReaper(ctx)
	cancel() // Should not panic or leak.
}

func TestOnChangeCallback(t *testing.T) {
	al := New()

	var added []netip.Addr
	var removed []netip.Addr
	al.SetOnChange(func(ip netip.Addr, isAdded bool) {
		if isAdded {
			added = append(added, ip)
		} else {
			removed = append(removed, ip)
		}
	})

	ip := netip.MustParseAddr("93.184.216.34")
	al.Add(ip, "example.com", 5*time.Minute)
	al.Remove(ip)

	if len(added) != 1 {
		t.Fatalf("expected 1 added callback, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed callback, got %d", len(removed))
	}
}

func TestInvalidIP(t *testing.T) {
	al := New()

	// Should not panic on invalid IPs.
	var invalid netip.Addr
	al.Add(invalid, "test.com", time.Minute)
	if al.Contains(invalid) {
		t.Fatal("expected invalid IP to not be in allowlist")
	}
	al.AddPermanent(invalid)
}

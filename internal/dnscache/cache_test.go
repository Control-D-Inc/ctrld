package dnscache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// msgWithECS builds an A query for name carrying an EDNS Client Subnet option, or none
// when family == 0.
func msgWithECS(name string, family uint16, prefix uint8, addr string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	if family == 0 {
		return m
	}
	m.SetEdns0(4096, true)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: prefix,
		Address:       net.ParseIP(addr),
	})
	return m
}

// answerWithA builds a cached answer holding a single A record with the given address.
func answerWithA(name, a string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	rr, err := dns.NewRR(dns.Fqdn(name) + " 300 IN A " + a)
	if err != nil {
		panic(err)
	}
	m.Answer = []dns.RR{rr}
	return m
}

func firstA(msg *dns.Msg) string {
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// TestCanonicalECS covers the key-partitioning helper: only a request with no ECS option
// collapses to the shared empty partition, while a carried /0 keeps its own family-scoped
// token (distinct from no-ECS, per RFC 7871 §7.3.1); host bits below the source prefix do
// not fragment the key, and different subnets / families produce different keys.
func TestCanonicalECS(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
		want string
	}{
		{"no ecs", msgWithECS("controld.com", 0, 0, ""), ""},
		// A carried ECS option is never "" (RFC 7871 §7.3.1), and IPv4 /0 vs
		// IPv6 /0 stay distinct; the address encoding must not change the token.
		{"ipv4 /0", msgWithECS("controld.com", 1, 0, "0.0.0.0"), "1/0/0.0.0.0"},
		{"ipv4 /0 empty addr", msgWithECS("controld.com", 1, 0, ""), "1/0/0.0.0.0"},
		{"ipv6 /0", msgWithECS("controld.com", 2, 0, "::"), "2/0/::"},
		{"ipv6 /0 empty addr", msgWithECS("controld.com", 2, 0, ""), "2/0/::"},
		{"ipv4 /24", msgWithECS("controld.com", 1, 24, "203.0.113.0"), "1/24/203.0.113.0"},
		{"ipv4 host bits masked", msgWithECS("controld.com", 1, 24, "203.0.113.7"), "1/24/203.0.113.0"},
		{"ipv6 /64", msgWithECS("controld.com", 2, 64, "2001:db8:1::"), "2/64/2001:db8:1::"},
		{"ipv6 host bits masked", msgWithECS("controld.com", 2, 64, "2001:db8:1::dead:beef"), "2/64/2001:db8:1::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalECS(tt.msg); got != tt.want {
				t.Fatalf("CanonicalECS = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNewKey_ECSPartition verifies the cache key distinguishes subnets while collapsing
// same-subnet requests, so the LRU cache cannot serve one subnet's records to another.
func TestNewKey_ECSPartition(t *testing.T) {
	const up = "https://dns.example/dns-query"
	subnetA := NewKey(msgWithECS("controld.com", 2, 64, "2001:db8:1::"), up)
	subnetB := NewKey(msgWithECS("controld.com", 2, 64, "2001:db8:2::"), up)
	subnetAHost := NewKey(msgWithECS("controld.com", 2, 64, "2001:db8:1::5"), up)
	ipv4 := NewKey(msgWithECS("controld.com", 1, 24, "203.0.113.0"), up)
	noECS := NewKey(msgWithECS("controld.com", 0, 0, ""), up)

	if subnetA == subnetB {
		t.Fatal("different subnets must not share a cache key")
	}
	if subnetA != subnetAHost {
		t.Fatal("same subnet (different host bits) must share a cache key")
	}
	if subnetA == ipv4 || subnetA == noECS || ipv4 == noECS {
		t.Fatal("different families / no-ECS must not collide")
	}
}

// TestLRUCache_ECSZeroPrefixDistinctFromNoECS is the regression test for the /0-vs-no-ECS
// collision (RFC 7871 §7.3.1). A query carrying an ECS /0 option is forwarded WITH ECS and
// may draw different upstream data, so its cached answer must never be served to a client
// that sent no ECS at all, nor may IPv4 /0 and IPv6 /0 cross-serve each other.
func TestLRUCache_ECSZeroPrefixDistinctFromNoECS(t *testing.T) {
	c, err := NewLRUCache(16)
	if err != nil {
		t.Fatalf("NewLRUCache: %v", err)
	}
	const up = "https://dns.example/dns-query"
	expire := time.Now().Add(time.Minute)

	noECS := msgWithECS("controld.com", 0, 0, "")
	zeroV4 := msgWithECS("controld.com", 1, 0, "0.0.0.0")
	zeroV6 := msgWithECS("controld.com", 2, 0, "::")

	// Only the IPv4 /0 query's answer is cached.
	c.Add(NewKey(zeroV4, up), NewValue(answerWithA("controld.com", "192.0.2.1"), expire))

	// A no-ECS client must NOT receive the ECS /0 cached answer.
	if got := c.Get(NewKey(noECS, up)); got != nil {
		t.Fatalf("no-ECS client received the ECS /0 cached record %q", firstA(got.Msg))
	}
	// An IPv6 /0 client must NOT receive the IPv4 /0 answer.
	if got := c.Get(NewKey(zeroV6, up)); got != nil {
		t.Fatalf("IPv6 /0 client received the IPv4 /0 cached record %q", firstA(got.Msg))
	}
	// The IPv4 /0 client still hits its own entry.
	if got := c.Get(NewKey(zeroV4, up)); got == nil || firstA(got.Msg) != "192.0.2.1" {
		t.Fatalf("IPv4 /0 lost its own cached record: %v", got)
	}

	// The no-ECS partition is independent and does not corrupt the /0 entry.
	c.Add(NewKey(noECS, up), NewValue(answerWithA("controld.com", "198.51.100.1"), expire))
	if got := c.Get(NewKey(noECS, up)); got == nil || firstA(got.Msg) != "198.51.100.1" {
		t.Fatalf("no-ECS partition wrong record: %v", got)
	}
	if got := c.Get(NewKey(zeroV4, up)); got == nil || firstA(got.Msg) != "192.0.2.1" {
		t.Fatalf("IPv4 /0 record corrupted by no-ECS insert: %v", got)
	}
}

// TestLRUCache_ECSNoCrossSubnetServe is the real cache-path regression test for #564:
// an entry populated for subnet A must never be returned to a client in subnet B, even
// though the question (name/type/class/upstream) is identical. The two subnets carry
// different A records; the second client must get its own record or a miss, never A's.
func TestLRUCache_ECSNoCrossSubnetServe(t *testing.T) {
	c, err := NewLRUCache(16)
	if err != nil {
		t.Fatalf("NewLRUCache: %v", err)
	}
	const up = "https://dns.example/dns-query"
	expire := time.Now().Add(time.Minute)

	reqA := msgWithECS("controld.com", 2, 64, "2001:db8:1::")
	reqB := msgWithECS("controld.com", 2, 64, "2001:db8:2::")

	// Only subnet A's answer (A record 192.0.2.1) is cached.
	c.Add(NewKey(reqA, up), NewValue(answerWithA("controld.com", "192.0.2.1"), expire))

	// A client in subnet B must NOT hit subnet A's entry.
	if got := c.Get(NewKey(reqB, up)); got != nil {
		t.Fatalf("subnet B received subnet A's cached record %q; cache is not ECS-partitioned", firstA(got.Msg))
	}

	// Subnet A still hits its own entry.
	if got := c.Get(NewKey(reqA, up)); got == nil || firstA(got.Msg) != "192.0.2.1" {
		t.Fatalf("subnet A lost its own cached record: %+v", got)
	}

	// Now cache subnet B's distinct answer and confirm the two never cross.
	c.Add(NewKey(reqB, up), NewValue(answerWithA("controld.com", "198.51.100.1"), expire))
	if got := c.Get(NewKey(reqB, up)); got == nil || firstA(got.Msg) != "198.51.100.1" {
		t.Fatalf("subnet B got the wrong record: %v", got)
	}
	if got := c.Get(NewKey(reqA, up)); got == nil || firstA(got.Msg) != "192.0.2.1" {
		t.Fatalf("subnet A record corrupted by subnet B insert: %v", got)
	}

	// A second host within subnet A shares the partition (cache hit with A's record).
	reqAHost := msgWithECS("controld.com", 2, 64, "2001:db8:1::9")
	if got := c.Get(NewKey(reqAHost, up)); got == nil || firstA(got.Msg) != "192.0.2.1" {
		t.Fatalf("same-subnet host missed the shared cache entry: %v", got)
	}
}

package ctrld

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Test_SetCacheReply_DoesNotRewriteECS documents the post-#564 contract: cross-client
// correctness is guaranteed by partitioning the cache/singleflight keys by ECS
// (dnscache.CanonicalECS), NOT by rewriting the cached answer's ECS option. Rewriting the
// ECS metadata while leaving the Answer records scoped to another subnet would violate
// RFC 7871 §7.3 and make forwarders accept a wrong-subnet answer. SetCacheReply must
// therefore leave the answer's ECS untouched.
func Test_SetCacheReply_DoesNotRewriteECS(t *testing.T) {
	answer := new(dns.Msg)
	answer.SetQuestion(dns.Fqdn("controld.com"), dns.TypeA)
	answer.SetEdns0(4096, false)
	cachedSubnet := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        2,
		SourceNetmask: 64,
		SourceScope:   64,
		Address:       net.ParseIP("2001:db8:1::"),
	}
	answer.IsEdns0().Option = append(answer.IsEdns0().Option, cachedSubnet)

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("controld.com"), dns.TypeA)
	req.SetEdns0(4096, true)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        2,
		SourceNetmask: 64,
		Address:       net.ParseIP("2001:db8:2::"),
	})

	SetCacheReply(answer, req, dns.RcodeSuccess)

	var got *dns.EDNS0_SUBNET
	for _, o := range answer.IsEdns0().Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			got = e
			break
		}
	}
	if got == nil {
		t.Fatal("SetCacheReply dropped the answer's ECS option")
	}
	if want := net.ParseIP("2001:db8:1::"); !got.Address.Equal(want) {
		t.Fatalf("SetCacheReply rewrote the answer ECS to the requester's subnet: got %v, want %v (unchanged)", got.Address, want)
	}
	if got.SourceScope != 64 {
		t.Fatalf("SetCacheReply altered the answer ECS scope: got %d, want 64 (unchanged)", got.SourceScope)
	}
}

package ctrld

import (
	"github.com/miekg/dns"
)

// SetCacheReply extracts and stores the necessary data from the message for a cached answer.
func SetCacheReply(answer, msg *dns.Msg, code int) {
	answer.SetRcode(msg, code)
	cCookie := getEdns0Cookie(msg.IsEdns0())
	sCookie := getEdns0Cookie(answer.IsEdns0())
	if cCookie != nil && sCookie != nil {
		// Client cookie is fixed size 8 bytes, Server cookie is variable size 8 -> 32 bytes.
		// See https://datatracker.ietf.org/doc/html/rfc7873#section-4
		sCookie.Cookie = cCookie.Cookie[:16] + sCookie.Cookie[16:]
	}
	// NOTE: the answer's EDNS Client Subnet (ECS) is intentionally left as the
	// upstream returned it. Correctness across clients is guaranteed by
	// partitioning the cache and singleflight keys by ECS (see
	// dnscache.CanonicalECS), so a cache hit only ever serves an answer that was
	// resolved for the requester's own subnet. Rewriting the ECS option here
	// without re-scoping the Answer records would violate RFC 7871 §7.3.
}

// getEdns0Cookie returns Edns0 cookie from *dns.OPT if present.
func getEdns0Cookie(opt *dns.OPT) *dns.EDNS0_COOKIE {
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_COOKIE); ok {
			return e
		}
	}
	return nil
}

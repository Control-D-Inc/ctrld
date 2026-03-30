//go:build !darwin

package cli

import "github.com/miekg/dns"

// wrapIPv6Handler is a no-op on non-darwin platforms. The raw IPv6 response
// writer is only needed on macOS where pf's rdr preserves the original global
// unicast source address, and the kernel rejects sendmsg from [::1] to it.
func wrapIPv6Handler(h dns.Handler) dns.Handler {
	return h
}

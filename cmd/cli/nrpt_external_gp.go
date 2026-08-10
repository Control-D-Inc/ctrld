package cli

import (
	"errors"
	"net/netip"
	"strings"
)

const nrptRuleName = `CtrldCatchAll`

// errGPNRPTVerified marks an intercept startup failure that happened while an externally
// managed (Group Policy) NRPT catch-all was proved - by probe, not by registry shape
// alone - to be routing DNS to this listener. It is the difference between "intercept
// failed but DNS still reaches ctrld" and "intercept failed and nothing is filtering",
// which is what decides whether the interface-DNS fallback must run.
//
// Only the Windows path produces it, but setDNS is shared, so the sentinel and its
// predicate live here with the other platform-neutral NRPT helpers.
var errGPNRPTVerified = errors.New("GP-managed NRPT verified routing to ctrld")

// errGPNRPTIneffective marks a startup that ends with externally managed NRPT owning the
// namespace while no probe has proved it routes to ctrld. DNS is not reaching ctrld, but
// adapter DNS was deliberately preserved and no ctrld rule may be written beside an
// administrator's catch-all - so this is a failed start that must not take the
// interface-DNS fallback either.
var errGPNRPTIneffective = errors.New("GP-managed NRPT owns the namespace but no probe reached ctrld")

// interceptFailedWithVerifiedExternalDNS reports whether an intercept startup failure
// happened while externally managed DNS policy was verified to be routing to ctrld.
func interceptFailedWithVerifiedExternalDNS(err error) bool {
	return errors.Is(err, errGPNRPTVerified)
}

// interceptFailedUnderExternalDNSPolicy reports whether an intercept startup failure
// happened while externally managed DNS policy owned the namespace, whether or not it was
// proved to route. Either way the interface-DNS fallback must not run: adapter DNS was
// preserved on purpose, and rewriting it would violate the policy ctrld just deferred to.
// Only the verified case is a successful start.
func interceptFailedUnderExternalDNSPolicy(err error) bool {
	return errors.Is(err, errGPNRPTVerified) || errors.Is(err, errGPNRPTIneffective)
}

// isExternalGPCatchAll recognizes only a single catch-all namespace that is not
// ctrld's deterministic GP key. Registry access stays in the Windows file; this
// pure classifier is shared with host-runnable tests.
func isExternalGPCatchAll(ruleName string, namespaces []string) bool {
	return ruleName != "" && !strings.EqualFold(ruleName, nrptRuleName) && len(namespaces) == 1 && strings.TrimSpace(namespaces[0]) == "."
}

func isMatchingGPNRPTRule(ruleName string, namespaces []string, dnsServers, listenerIP string) bool {
	if !isExternalGPCatchAll(ruleName, namespaces) {
		return false
	}
	server, err := netip.ParseAddr(strings.TrimSpace(dnsServers))
	if err != nil {
		return false
	}
	listener, err := netip.ParseAddr(strings.TrimSpace(listenerIP))
	if err != nil {
		return false
	}
	return server.Unmap() == listener.Unmap()
}

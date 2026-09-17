package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// internalDomainUpstreamPrefix names the upstreams generated for organization
// Internal Domains that select explicit resolvers. The prefix is what tells
// proxy() that a rule is served only by configured resolvers, so it
// must not collide with the numeric keys used for the Control D upstream.
const internalDomainUpstreamPrefix = "internal_"

// internalDomainUpstreamName is the Name given to every generated Internal
// Domain upstream. Together with the key prefix and the legacy type it is what
// distinguishes an upstream ctrld generated from one an endpoint custom
// configuration happens to name the same way.
const internalDomainUpstreamName = "Internal Domain resolver"

// internalDomainsSummary counts the outcome of applying Internal Domains. It
// carries no domain names and no resolver addresses: info and warning logs
// report these counts, and the values themselves stay at debug level.
type internalDomainsSummary struct {
	domains   int // domains that produced rules
	osMode    int // domains routed to the OS/default resolver
	explicit  int // domains routed to configured resolvers
	resolvers int // explicit resolver upstreams generated
	skipped   int // entries dropped: unusable domain, no usable resolver, or duplicate
	preempted int // domains already covered by a higher precedence rule
}

// empty reports whether nothing was applied and nothing was dropped, which is
// the shape of a config whose split_dns list was absent or empty.
func (s internalDomainsSummary) empty() bool {
	return s.domains == 0 && s.skipped == 0 && s.preempted == 0
}

// internalDomainLabelOK reports whether label satisfies the ASCII hostname
// contract the API validates against: 1-63 characters, letters, digits and
// hyphens only, and no leading or trailing hyphen. Punycode labels are plain
// LDH and pass unchanged.
func internalDomainLabelOK(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// normalizeInternalDomain canonicalizes a domain to the form policy rules are
// matched in, or returns "" if it is not a domain ctrld will route.
//
// Canonicalization is limited to what cannot change which names match:
// lowercasing, surrounding whitespace, the root dot, and a leading "*." (the
// caller adds the wildcard rule itself). What remains is validated as an ASCII
// hostname suffix rather than screened against a list of bad characters,
// because a denylist admits whatever it forgot: an embedded newline, quote,
// colon or control character would otherwise reach a generated rule.
//
// An invalid entry is rejected rather than repaired. Deleting the offending
// characters would produce a different suffix from the one that was
// configured, and routing a private domain to the wrong place is worse than
// not routing it. Single-label names stay supported.
//
// The rule matches the API's own validation, so a value the dashboard accepted
// passes here too.
func normalizeInternalDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return ""
	}
	for _, label := range strings.Split(d, ".") {
		if !internalDomainLabelOK(label) {
			return ""
		}
	}
	return d
}

// internalDomainEndpoint converts a resolver to an endpoint ctrld can dial.
// A bare IPv4 or IPv6 address gets the default DNS port; and address that
// already carries a port keeps it. Anything else is rejected, so a malformed
// entry cannot silently become a hostname lookup.
func internalDomainEndpoint(resolver string) (string, bool) {
	s := strings.TrimSpace(resolver)
	if s == "" {
		return "", false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(addr.String(), "53"), true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", false
	}
	return net.JoinHostPort(addr.String(), port), true
}

// internalDomainMode reports whether entry selects explicit resolvers, and
// whether ctrld understands its mode at all.
//
// Mode is authoritative when the API sends it. "os" ignores any resolver
// addresses the entry still carries, so switching a domain back to the OS
// resolver cannot be undone by addresses a previous selection left behind;
// "resolvers" stays explicit even when the list it points at turns out to be
// unusable, rather than silently becoming OS resolution. An empty mode is a
// deployment that predates the field, where the list is the only signal.
//
// An unrecognized mode is not guessed at: routing a private domain by guess is
// the disclosure this feature exists to prevent.
func internalDomainMode(entry controld.SplitDNS) (explicit, known bool) {
	switch strings.ToLower(strings.TrimSpace(entry.Mode)) {
	case controld.SplitDNSModeOS:
		return false, true
	case controld.SplitDNSModeResolvers:
		return true, true
	case "":
		return len(entry.Resolvers) > 0, true
	default:
		return false, false
	}
}

// internalDomainRouting returns the endpoints an entry routes to, or a reason
// it cannot be used. No endpoints and no reason means OS resolution.
//
// Generation and refresh comparison both go through here, so the two can never
// disagree about what an entry means.
func internalDomainRouting(entry controld.SplitDNS) (endpoints []string, reason string) {
	explicit, known := internalDomainMode(entry)
	if !known {
		return nil, "unknown_mode"
	}
	if !explicit {
		return nil, ""
	}
	endpoints = make([]string, 0, len(entry.Resolvers))
	for _, resolver := range entry.Resolvers {
		if endpoint, ok := internalDomainEndpoint(resolver); ok {
			endpoints = append(endpoints, endpoint)
		}
	}
	// The administrator selected explicit resolvers and none of them parsed.
	// Falling back to the OS resolver would turn that selection into a
	// different one, so the entry is dropped and the domain keeps its normal
	// path instead.
	if len(endpoints) == 0 {
		return nil, "no_usable_resolver"
	}
	return endpoints, ""
}

// internalDomainRuleExists reports whether the listener policy already routes
// source. Internal Domains never overwrite a rule that is already there, which
// is what gives Magic Folder excludes and endpoint custom configuration
// precedence over them.
func internalDomainRuleExists(lc *ctrld.ListenerConfig, source string) bool {
	if lc.Policy == nil {
		return false
	}
	for _, rule := range lc.Policy.Rules {
		if _, ok := rule[source]; ok {
			return true
		}
	}
	return false
}

// internalDomainSpecificity ranks a normalized domain by label count, which is
// how much of a name it pins down. "z.example.com" ranks above "example.com".
func internalDomainSpecificity(domain string) int {
	if domain == "" {
		return 0
	}
	return strings.Count(domain, ".") + 1
}

// orderInternalDomainsBySpecificity returns entries most-specific first.
//
// upstreamFor matches policy rules in slice order and takes the first hit, so
// generation order is routing precedence. The API sorts Internal Domains
// bytewise by domain, which puts a parent suffix ahead of its children:
// appending in that order would let "*.example.com" swallow every query a
// configured "z.example.com" rule was meant to answer, and the administrator
// never chose that priority. Overlapping suffixes are permitted, so the more
// specific one has to win.
//
// The sort is stable, so entries that are equally specific keep API order and
// the first of two identical domains still wins the duplicate check.
func orderInternalDomainsBySpecificity(entries []controld.SplitDNS) []controld.SplitDNS {
	ordered := make([]controld.SplitDNS, len(entries))
	copy(ordered, entries)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := normalizeInternalDomain(ordered[i].Domain), normalizeInternalDomain(ordered[j].Domain)
		if sa, sb := internalDomainSpecificity(a), internalDomainSpecificity(b); sa != sb {
			return sa > sb
		}
		return a < b
	})
	return ordered
}

// applyInternalDomains adds a policy rule per organization Internal Domain to
// every listener in cfg, and the upstreams those rules need.
//
// Each domain contributes two rules, the domain itself and "*." + domain, which
// is how a suffix and all of its subdomains are matched. An entry with no
// resolvers routes to the OS/default resolver by way of an empty upstream list,
// the same representation Magic Folder excludes use. An entry with resolvers
// gets one generated upstream per address, listed in configured order so the
// later ones act as failover for the first.
//
// cfg is rebuilt from the API response on every fetch, so this function is the
// only writer of internal_* upstreams: a removed domain leaves nothing behind.
func applyInternalDomains(cfg *ctrld.Config, entries []controld.SplitDNS) internalDomainsSummary {
	var summary internalDomainsSummary
	if len(entries) == 0 || len(cfg.Listener) == 0 {
		return summary
	}
	if cfg.Upstream == nil {
		cfg.Upstream = make(map[string]*ctrld.UpstreamConfig)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range orderInternalDomainsBySpecificity(entries) {
		domain := normalizeInternalDomain(entry.Domain)
		if domain == "" {
			mainLog.Load().Debug().Msgf("internal domains: skipping unusable domain %q", entry.Domain)
			summary.skipped++
			continue
		}
		if _, dup := seen[domain]; dup {
			mainLog.Load().Debug().Msgf("internal domains: skipping duplicate domain %q", domain)
			summary.skipped++
			continue
		}

		// Routing is resolved, and preemption decided, before anything is
		// written: an entry that cannot be used, or a domain already covered by
		// a higher precedence rule, must not leave a generated upstream behind
		// with no rule referring to it.
		endpoints, reason := internalDomainRouting(entry)
		if reason != "" {
			mainLog.Load().Debug().Msgf("internal domains: skipping %q: %s", domain, reason)
			summary.skipped++
			continue
		}
		seen[domain] = struct{}{}

		sources := []string{domain, "*." + domain}
		free := make(map[*ctrld.ListenerConfig][]string, len(cfg.Listener))
		anyFree := false
		for _, lc := range cfg.Listener {
			for _, source := range sources {
				if internalDomainRuleExists(lc, source) {
					mainLog.Load().Debug().Msgf("internal domains: %q already routed by a higher precedence rule", source)
					continue
				}
				free[lc] = append(free[lc], source)
				anyFree = true
			}
		}
		if !anyFree {
			summary.preempted++
			continue
		}

		targets := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			key := internalDomainUpstreamPrefix + strconv.Itoa(summary.resolvers)
			cfg.Upstream[key] = &ctrld.UpstreamConfig{
				Name:     internalDomainUpstreamName,
				Type:     ctrld.ResolverTypeLegacy,
				Endpoint: endpoint,
				Timeout:  5000,
			}
			targets = append(targets, upstreamPrefix+key)
			summary.resolvers++
		}
		for lc, sources := range free {
			if lc.Policy == nil {
				lc.Policy = &ctrld.ListenerPolicyConfig{}
			}
			for _, source := range sources {
				lc.Policy.Rules = append(lc.Policy.Rules, ctrld.Rule{source: targets})
			}
		}
		summary.domains++
		if len(targets) == 0 {
			summary.osMode++
			mainLog.Load().Debug().Msgf("internal domains: %q routed to the OS resolver", domain)
		} else {
			summary.explicit++
			mainLog.Load().Debug().Msgf("internal domains: %q routed to %v", domain, targets)
		}
	}
	return summary
}

// isGeneratedInternalDomainUpstream reports whether a cfg.Upstream entry is one
// applyInternalDomains created.
//
// Generated Internal Domain resolvers are part of the managed Control D
// configuration, not upstreams the endpoint operator chose, so eligibility
// checks that ask "is this a plain single-upstream Control D install" must not
// count them. The key prefix alone is not proof of that, because an endpoint
// custom configuration replaces the generated config outright and could name an
// upstream anything; the shape this function checks is only produced here.
func isGeneratedInternalDomainUpstream(name string, uc *ctrld.UpstreamConfig) bool {
	return uc != nil &&
		strings.HasPrefix(name, internalDomainUpstreamPrefix) &&
		uc.Type == ctrld.ResolverTypeLegacy &&
		uc.Name == internalDomainUpstreamName
}

// isInternalDomainUpstream reports whether an upstream reference was generated
// for an Internal Domain with explicit resolvers.
func isInternalDomainUpstream(upstream string) bool {
	return strings.HasPrefix(upstream, upstreamPrefix+internalDomainUpstreamPrefix)
}

// internalDomainExplicitUpstreams reports whether every upstream serving a
// query is an configured Internal Domain resolver.
//
// proxy() uses this to keep such a query off the OS-resolver catch-all when the
// configured resolvers are unreachable: the administrator selected those
// resolvers and no other, so a private name must fail rather than be sent
// somewhere it was not meant to go. It also keeps an unreachable internal
// resolver from triggering the endpoint-wide recovery flow, which exists for
// the loss of general DNS, not for one unavailable internal server.
func internalDomainExplicitUpstreams(upstreams []string) bool {
	if len(upstreams) == 0 {
		return false
	}
	for _, upstream := range upstreams {
		if !isInternalDomainUpstream(upstream) {
			return false
		}
	}
	return true
}

// internalDomainsEqual reports whether two Internal Domains lists would produce
// the same routing. Domains are compared in canonical form and independently of
// the order the API returned them, so an unchanged list does not trigger a
// reload on every refresh. Resolver order is significant: it is the order the
// administrator chose, and it decides which resolver is tried first.
func internalDomainsEqual(a, b []controld.SplitDNS) bool {
	canonical := func(entries []controld.SplitDNS) []controld.SplitDNS {
		out := make([]controld.SplitDNS, 0, len(entries))
		for _, entry := range entries {
			domain := normalizeInternalDomain(entry.Domain)
			if domain == "" {
				continue
			}
			// Entries that cannot be used route nothing, so they cannot make
			// an otherwise unchanged list look changed.
			endpoints, reason := internalDomainRouting(entry)
			if reason != "" {
				continue
			}
			out = append(out, controld.SplitDNS{Domain: domain, Resolvers: endpoints})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
		return out
	}
	x, y := canonical(a), canonical(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i].Domain != y[i].Domain || !slices.Equal(x[i].Resolvers, y[i].Resolvers) {
			return false
		}
	}
	return true
}

// internalDomainFailureReason classifies a resolver failure for logging. The
// error itself names the endpoint that could not be reached, so only this
// classification may appear above debug level.
func internalDomainFailureReason(err error) string {
	switch {
	case err == nil:
		return "no_answer"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "source_unavailable"
	case ctrldnet.IsUnreachable(err):
		return "unreachable"
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	return "error"
}

// isGeneratedInternalDomainUpstreamRef is isGeneratedInternalDomainUpstream for
// call sites that hold an "upstream.<key>" reference rather than the bare key.
func isGeneratedInternalDomainUpstreamRef(upstream string, uc *ctrld.UpstreamConfig) bool {
	return isGeneratedInternalDomainUpstream(strings.TrimPrefix(upstream, upstreamPrefix), uc)
}

// logUpstreamProbeFailure reports a background probe failure against an
// upstream.
//
// Loop checking and recovery checking run on timers, so for a generated
// Internal Domain resolver they would publish the organization's private
// address without any user ever querying the domain. They get the same
// treatment as a query failure: endpoint and the address-bearing error at
// debug, a classification above it, so the outcome stays visible while the
// address does not.
func (p *prog) logUpstreamProbeFailure(generated bool, uc *ctrld.UpstreamConfig, err error, level func() *ctrld.LogEvent, format string, args ...any) {
	detail := append([]any{}, args...)
	if !generated {
		level().Err(err).Msgf(format+" for upstream: %q, endpoint: %q", append(detail, uc.Name, uc.Endpoint)...)
		return
	}
	p.Debug().Err(err).Msgf(format+" for upstream: %q, endpoint: %q", append(detail, uc.Name, uc.Endpoint)...)
	level().Str("failure", internalDomainFailureReason(err)).
		Msgf(format+" for an Internal Domain resolver", detail...)
}

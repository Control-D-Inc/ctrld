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
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// internalDomainUpstreamPrefix names the upstreams generated for organization
// Internal Domains that select explicit resolvers. It must not collide with
// the numeric key used for the Control D upstream. The key only names the
// upstream: what identifies it as generated, and in which mode, is
// UpstreamConfig.InternalDomain, which no configuration file can set.
const internalDomainUpstreamPrefix = "internal_"

// Values of UpstreamConfig.InternalDomain on a generated upstream.
const (
	// internalDomainUpstreamFallback serves an Internal Domain in explicit
	// resolver with network fallback mode.
	internalDomainUpstreamFallback = "fallback"
	// internalDomainUpstreamOnly serves an Internal Domain in explicit
	// resolver only mode: its answer or failure is final.
	internalDomainUpstreamOnly = "only"
)

// internalDomainUpstreamName is the Name given to every generated Internal
// Domain upstream. It is only a display label: what identifies an upstream as
// generated is UpstreamConfig.InternalDomain, which no configuration can set.
const internalDomainUpstreamName = "Internal Domain resolver"

// internalDomainsSummary counts the outcome of applying Internal Domains. It
// carries no domain names and no resolver addresses: info and warning logs
// report these counts, and the values themselves stay at debug level.
type internalDomainsSummary struct {
	domains   int // domains that produced rules
	osMode    int // domains routed to the OS/default resolver
	explicit  int // domains routed to configured resolvers
	only      int // explicit domains with no network fallback
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

// internalDomainResolution is how an Internal Domain is resolved.
type internalDomainResolution int

const (
	// internalDomainViaOS is the "network default" mode: the endpoint's
	// OS/default resolver.
	internalDomainViaOS internalDomainResolution = iota
	// internalDomainViaResolvers is the configured resolvers first, then the
	// active network and VPN resolvers. The default explicit selection.
	internalDomainViaResolvers
	// internalDomainViaResolversOnly is the configured resolvers and nothing
	// else.
	internalDomainViaResolversOnly
)

// internalDomainMode reports how entry is resolved, and whether ctrld
// understands its mode at all.
//
// Mode is authoritative when the API sends it. "os" ignores any resolver
// addresses the entry still carries, so switching a domain back to the OS
// resolver cannot be undone by addresses a previous selection left behind;
// the explicit modes stay explicit even when the list they point at turns out
// to be unusable, rather than silently becoming OS resolution. An empty mode
// is a deployment that predates the field, where the list is the only signal,
// and an explicit list gets the default explicit mode.
//
// An unrecognized mode is not guessed at: routing a private domain by guess is
// the disclosure this feature exists to prevent. It fails closed instead. With
// resolvers it is resolved as explicit resolver only, through the resolvers the
// administrator chose and nothing else, so a wire value this build does not
// know, such as a renamed strict mode, cannot send the domain to the Control D
// upstream or the network. Without resolvers there is nothing to fail closed
// to, so the entry is reported as unknown and dropped.
func internalDomainMode(entry controld.SplitDNS) (resolution internalDomainResolution, known bool) {
	switch strings.ToLower(strings.TrimSpace(entry.Mode)) {
	case controld.SplitDNSModeOS:
		return internalDomainViaOS, true
	case controld.SplitDNSModeResolvers:
		return internalDomainViaResolvers, true
	case controld.SplitDNSModeResolversOnly:
		return internalDomainViaResolversOnly, true
	case "":
		if len(entry.Resolvers) > 0 {
			return internalDomainViaResolvers, true
		}
		return internalDomainViaOS, true
	default:
		if len(entry.Resolvers) > 0 {
			return internalDomainViaResolversOnly, true
		}
		return internalDomainViaOS, false
	}
}

// internalDomainModeRecognized reports whether mode is one this build knows,
// as opposed to one internalDomainMode resolves by failing closed.
func internalDomainModeRecognized(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", controld.SplitDNSModeOS, controld.SplitDNSModeResolvers, controld.SplitDNSModeResolversOnly:
		return true
	}
	return false
}

// internalDomainRouting returns how an entry is resolved and the endpoints it
// routes to, or a reason it cannot be used. No endpoints and no reason means
// OS resolution.
//
// Generation and refresh comparison both go through here, so the two can never
// disagree about what an entry means.
func internalDomainRouting(entry controld.SplitDNS) (resolution internalDomainResolution, endpoints []string, reason string) {
	resolution, known := internalDomainMode(entry)
	if !known {
		return resolution, nil, "unknown_mode"
	}
	if resolution == internalDomainViaOS {
		return resolution, nil, ""
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
		return resolution, nil, "no_usable_resolver"
	}
	return resolution, endpoints, ""
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
// later ones act as failover for the first. Those upstreams carry the mode in
// UpstreamConfig.InternalDomain.
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
		resolution, endpoints, reason := internalDomainRouting(entry)
		if reason != "" {
			mainLog.Load().Debug().Msgf("internal domains: skipping %q: %s", domain, reason)
			summary.skipped++
			continue
		}
		if !internalDomainModeRecognized(entry.Mode) {
			mainLog.Load().Debug().Msgf("internal domains: %q has unrecognized mode %q; using its resolvers only", domain, entry.Mode)
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

		marker := internalDomainUpstreamFallback
		if resolution == internalDomainViaResolversOnly {
			marker = internalDomainUpstreamOnly
		}
		targets := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			key := internalDomainUpstreamPrefix + strconv.Itoa(summary.resolvers)
			cfg.Upstream[key] = &ctrld.UpstreamConfig{
				Name:           internalDomainUpstreamName,
				Type:           ctrld.ResolverTypeLegacy,
				Endpoint:       endpoint,
				Timeout:        5000,
				InternalDomain: marker,
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
			if resolution == internalDomainViaResolversOnly {
				summary.only++
			}
			mainLog.Load().Debug().Msgf("internal domains: %q routed to %v", domain, targets)
		}
	}
	return summary
}

// isGeneratedInternalDomainUpstream reports whether uc is an upstream
// applyInternalDomains created.
//
// Generated Internal Domain resolvers are part of the managed Control D
// configuration, not upstreams the endpoint operator chose, so eligibility
// checks that ask "is this a plain single-upstream Control D install" must not
// count them. Neither the key nor any other configurable field is proof of
// that: a local config or an endpoint custom configuration can name an upstream
// anything and give it any type and name. Only the InternalDomain marker is,
// because ctrld sets it and no configuration file can.
func isGeneratedInternalDomainUpstream(uc *ctrld.UpstreamConfig) bool {
	return uc != nil && uc.InternalDomain != ""
}

// internalDomainUpstream returns the generated Internal Domain upstream an
// "upstream.<key>" reference names, or nil if it names any other upstream.
func (p *prog) internalDomainUpstream(upstream string) *ctrld.UpstreamConfig {
	if p.cfg == nil {
		return nil
	}
	uc := p.cfg.Upstream[strings.TrimPrefix(upstream, upstreamPrefix)]
	if !isGeneratedInternalDomainUpstream(uc) {
		return nil
	}
	return uc
}

// isInternalDomainUpstream reports whether an upstream reference names a
// generated Internal Domain resolver, in either explicit mode.
func (p *prog) isInternalDomainUpstream(upstream string) bool {
	return p.internalDomainUpstream(upstream) != nil
}

// internalDomainExplicitUpstreams reports whether every upstream serving a
// query is a configured Internal Domain resolver, in either explicit mode.
//
// proxy() uses this to try the configured resolvers before anything else, and
// to keep such a query off the OS-resolver catch-all when they fail: that
// catch-all may reach public nameservers, and a private name must not be sent
// somewhere it was not meant to go. In fallback mode proxy() tries the
// network resolvers instead (see internalDomainFallbackUpstreams). It also
// keeps an unreachable internal resolver from triggering the endpoint-wide
// recovery flow, which exists for the loss of general DNS, not for one
// unavailable internal server.
func (p *prog) internalDomainExplicitUpstreams(upstreams []string) bool {
	if len(upstreams) == 0 {
		return false
	}
	for _, upstream := range upstreams {
		if !p.isInternalDomainUpstream(upstream) {
			return false
		}
	}
	return true
}

// internalDomainFallbackUpstreams reports whether upstreams are the configured
// resolvers of an Internal Domain in explicit-with-network-fallback mode, whose
// failure, SERVFAIL or NXDOMAIN hands the query to the active network and VPN
// resolvers.
func (p *prog) internalDomainFallbackUpstreams(upstreams []string) bool {
	if len(upstreams) == 0 {
		return false
	}
	for _, upstream := range upstreams {
		uc := p.internalDomainUpstream(upstream)
		if uc == nil || uc.InternalDomain != internalDomainUpstreamFallback {
			return false
		}
	}
	return true
}

// internalDomainFallbackRcode reports whether a configured resolver's answer
// sends a fallback-mode query on to the next resolver. SERVFAIL means the
// resolver could not answer, and NXDOMAIN may only mean it does not know a
// name the local network's resolver does. REFUSED and NOTIMP mean it will not
// serve this endpoint, as an organization resolver with an access list answers
// an endpoint off the organization network, which is closer to unreachable
// than to an answer. Any other answer is final, including an empty NOERROR:
// the name exists, it just has no record of that type.
func internalDomainFallbackRcode(rcode int) bool {
	switch rcode {
	case dns.RcodeServerFailure, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotImplemented:
		return true
	}
	return false
}

// internalDomainsEqual reports whether two Internal Domains lists would produce
// the same routing. Domains are compared in canonical form and independently of
// the order the API returned them, so an unchanged list does not trigger a
// reload on every refresh. Resolver order is significant: it is the order the
// administrator chose, and it decides which resolver is tried first. The mode
// is significant too, including a switch between the two explicit modes.
func internalDomainsEqual(a, b []controld.SplitDNS) bool {
	type route struct {
		domain     string
		resolution internalDomainResolution
		endpoints  []string
	}
	canonical := func(entries []controld.SplitDNS) []route {
		out := make([]route, 0, len(entries))
		for _, entry := range entries {
			domain := normalizeInternalDomain(entry.Domain)
			if domain == "" {
				continue
			}
			// Entries that cannot be used route nothing, so they cannot make
			// an otherwise unchanged list look changed.
			resolution, endpoints, reason := internalDomainRouting(entry)
			if reason != "" {
				continue
			}
			out = append(out, route{domain: domain, resolution: resolution, endpoints: endpoints})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].domain < out[j].domain })
		return out
	}
	x, y := canonical(a), canonical(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i].domain != y[i].domain || x[i].resolution != y[i].resolution || !slices.Equal(x[i].endpoints, y[i].endpoints) {
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

// logUpstreamProbeFailure reports a background probe failure against the
// upstream that the reference upstream names.
//
// Loop checking and recovery checking run on timers, so for a generated
// Internal Domain resolver they would publish the organization's private
// address without any user ever querying the domain. The name and the
// endpoint of any upstream are operator text that can hold a token, so both
// stay on the debug line. The leveled line names the upstream by its bounded
// name, so the outcome stays visible while the operator text does not. A
// generated Internal Domain resolver also trades the address-bearing error
// for a classification.
func logUpstreamProbeFailure(upstream string, uc *ctrld.UpstreamConfig, err error, level func() *zerolog.Event, format string, args ...any) {
	detail := append([]any{}, args...)
	mainLog.Load().Debug().Err(err).Msgf(format+" for upstream: %q, endpoint: %q", append(detail, uc.Name, uc.Endpoint)...)
	event := level().Str("upstream", journalUpstreamName(upstream))
	if !isGeneratedInternalDomainUpstream(uc) {
		event.Err(err).Msgf(format, detail...)
		return
	}
	event.Str("failure", internalDomainFailureReason(err)).
		Msgf(format+" for an Internal Domain resolver", detail...)
}

// betterInternalDomainNegative returns whichever of two negative answers a
// fallback-mode query should end with: NXDOMAIN over SERVFAIL, since a
// resolver that says the name does not exist has answered, and otherwise the
// first one seen.
func betterInternalDomainNegative(current, candidate *dns.Msg) *dns.Msg {
	switch {
	case candidate == nil:
		return current
	case current == nil:
		return candidate
	case candidate.Rcode == dns.RcodeNameError && current.Rcode != dns.RcodeNameError:
		return candidate
	}
	return current
}

// internalDomainVPNUpstream returns the upstream the network fallback uses for
// a VPN DNS server. A seam: VPN DNS servers are dialed on port 53, which a test
// fixture cannot listen on.
var internalDomainVPNUpstream = func(m *vpnDNSManager, server string) *ctrld.UpstreamConfig {
	return m.upstreamConfigFor(server)
}

// internalDomainOSResolve resolves msg through the OS resolver for the network
// fallback. A seam, so a test sees the context the fallback passes: that
// context is what keeps the private name off public nameservers.
var internalDomainOSResolve = func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resolver, err := ctrld.NewResolver(osUpstreamConfig)
	if err != nil {
		return nil, err
	}
	resolveCtx, cancel := osUpstreamConfig.Context(ctx)
	defer cancel()
	return resolver.Resolve(resolveCtx, msg)
}

// resolveInternalDomainOnNetwork is the network fallback of an Internal Domain
// in explicit-with-network-fallback mode. proxy() runs it once the configured
// resolvers have failed, or answered SERVFAIL or NXDOMAIN.
//
// It asks only resolvers that the endpoint's active network or VPN provides,
// in this order: VPN DNS servers whose domains match the query, then VPN DNS
// servers with no domains (both only in dns-intercept mode, where ctrld tracks
// them), then the OS resolver's LAN nameservers. The OS resolver is asked as a
// LAN-only query, so the private name never reaches a public nameserver, not
// even one DHCP supplied, nor ctrld's own public fallback. With no LAN
// nameserver the OS step sends nothing.
//
// The first NOERROR answer is returned as answer, including an empty one,
// which is final. Otherwise negative is the best SERVFAIL or NXDOMAIN answer
// seen. While Windows is serving retained VPN DNS state, a VPN transport
// failure stops the fallback before the OS resolver, as it does for VPN split
// routing.
func (p *prog) resolveInternalDomainOnNetwork(ctx context.Context, msg *dns.Msg) (answer, negative *dns.Msg) {
	domain := msg.Question[0].Name
	resolve := func(ctx context.Context, uc *ctrld.UpstreamConfig) (*dns.Msg, error) {
		resolver, err := ctrld.NewResolver(uc)
		if err != nil {
			return nil, err
		}
		resolveCtx, cancel := uc.Context(ctx)
		defer cancel()
		return resolver.Resolve(resolveCtx, msg)
	}
	// accept reports whether a network answer is final, and keeps a negative
	// one for the end.
	accept := func(source string, m *dns.Msg) bool {
		if !sameQuestion(msg, m) {
			ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain fallback: discarding answer from %s: question mismatch", source)
			return false
		}
		if m.Rcode == dns.RcodeSuccess {
			ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain fallback: %s answered %s", source, domain)
			return true
		}
		ctrld.Log(ctx, mainLog.Load().Debug(), "internal domain fallback: %s answered %s for %s",
			source, dns.RcodeToString[m.Rcode], domain)
		if internalDomainFallbackRcode(m.Rcode) {
			negative = betterInternalDomainNegative(negative, m)
		}
		return false
	}

	if dnsIntercept && p.vpnDNS != nil {
		var servers []string
		for _, server := range slices.Concat(p.vpnDNS.UpstreamForDomain(domain), p.vpnDNS.DomainlessServers()) {
			if !slices.Contains(servers, server) {
				servers = append(servers, server)
			}
		}
		var gotAnswer, gotTransportFailure bool
		for _, server := range servers {
			m, err := resolve(ctx, internalDomainVPNUpstream(p.vpnDNS, server))
			if m == nil {
				gotTransportFailure = true
				ctrld.Log(ctx, mainLog.Load().Debug().Err(err), "internal domain fallback: VPN DNS server %s failed", server)
				continue
			}
			gotAnswer = true
			p.vpnDNS.VPNDNSReachable()
			if accept("VPN DNS server "+server, m) {
				return m, nil
			}
		}
		if !gotAnswer && gotTransportFailure && p.vpnDNS.ShouldFailClosedAfterVPNDNSTransportFailure(domain, servers) {
			return nil, negative
		}
	}

	m, err := internalDomainOSResolve(ctrld.LanOnlyQueryCtx(ctx), msg)
	if m == nil {
		ctrld.Log(ctx, mainLog.Load().Debug().Err(err), "internal domain fallback: OS resolver LAN nameservers failed")
		return nil, negative
	}
	if accept("OS resolver", m) {
		return m, nil
	}
	return nil, negative
}

// internalDomainProbeInterval is how often, at most, a down fallback-mode
// Internal Domain resolver is re-checked in the background.
const internalDomainProbeInterval = 30 * time.Second

// internalDomainProber re-checks down fallback-mode Internal Domain resolvers
// in the background, and marks one up again when it answers.
//
// proxy() skips such a resolver while it is down, so that an endpoint away
// from the organization network goes to the network fallback without waiting
// on it. A generated resolver comes back up only by answering a query: it is
// excluded from recovery, and the loop checker leaves down upstreams alone. So
// without this re-check, a resolver that went down would stay skipped until
// the next reload, even once the endpoint is back on the organization network.
//
// The zero value is ready to use.
type internalDomainProber struct {
	mu   sync.Mutex
	last map[string]time.Time

	// now and start are seams, so a test controls the clock and runs the
	// re-check itself. nil means time.Now and a new goroutine.
	now   func() time.Time
	start func(func())
}

// probe re-checks upstream in the background, at most once per
// internalDomainProbeInterval, by sending it a copy of msg. The query goes to
// the organization's own resolver, which it was meant for anyway. Any DNS
// answer proves the resolver reachable, the same as on the query path, and
// marks it up in um; a failure leaves it down until the next re-check.
func (pr *internalDomainProber) probe(um *upstreamMonitor, upstream string, uc *ctrld.UpstreamConfig, msg *dns.Msg) {
	now := time.Now
	if pr.now != nil {
		now = pr.now
	}
	pr.mu.Lock()
	if last, ok := pr.last[upstream]; ok && now().Sub(last) < internalDomainProbeInterval {
		pr.mu.Unlock()
		return
	}
	if pr.last == nil {
		pr.last = make(map[string]time.Time)
	}
	pr.last[upstream] = now()
	pr.mu.Unlock()

	query := msg.Copy()
	run := func() {
		var answer *dns.Msg
		resolver, err := ctrld.NewResolver(uc)
		if err == nil {
			ctx, cancel := uc.Context(context.Background())
			answer, err = resolver.Resolve(ctx, query)
			cancel()
		}
		if answer == nil {
			mainLog.Load().Debug().Err(err).Msgf("internal domains: %s is still down", upstream)
			return
		}
		mainLog.Load().Debug().Msgf("internal domains: %s answered the re-check", upstream)
		um.noteSuccess(upstream)
	}
	if pr.start != nil {
		pr.start(run)
		return
	}
	go run()
}

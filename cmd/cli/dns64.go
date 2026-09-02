package cli

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
)

// DNS64 synthesis for IPv6-only networks WITHOUT client-side 464XLAT (no
// CLAT). On such networks the carrier's DNS64 resolver is load-bearing: it
// synthesizes AAAA records mapping IPv4-only destinations into the NAT64
// prefix, and there is no CLAT interface to carry real IPv4 traffic. When
// ctrld answers with genuine A records there, IPv4-only destinations become
// unreachable — DNS resolves but connectivity fails (issue companion to
// #533; tethering is unaffected because Apple/Android always provide CLAT).
//
// ctrld therefore performs its own RFC 6147-style synthesis after filtering:
// when the network is IPv6-only with no CLAT and a NAT64 prefix is known,
// an AAAA query whose (policy-approved) answer contains no AAAA records is
// re-resolved as an A query through the same upstream, and the A records are
// mapped into the NAT64 prefix. Blocked answers are never synthesized —
// synthesis runs on the answer the policy engine already approved.
//
// NAT64 prefix discovery uses RFC 7050: resolve AAAA for ipv4only.arpa
// through the network's own resolvers and derive the prefix from the
// embedded well-known IPv4 addresses (192.0.0.170/171). PREF64 router
// advertisements (RFC 8781) are not parsed; RFC 7050 covers the same
// networks without OS-specific RA plumbing.

const (
	// dns64RecheckInterval bounds how often network state (CLAT presence,
	// IPv4 availability, NAT64 prefix) is re-evaluated.
	dns64RecheckInterval = 5 * time.Minute
	// dns64WellKnownName is the RFC 7050 discovery name.
	dns64WellKnownName = "ipv4only.arpa."
	// dns64DiscoverTimeout bounds one background discovery attempt.
	dns64DiscoverTimeout = 5 * time.Second
)

// rfc7050WellKnown are the IPv4 addresses embedded in ipv4only.arpa AAAA
// answers on DNS64 networks (RFC 7050).
var rfc7050WellKnown = []netip.Addr{
	netip.AddrFrom4([4]byte{192, 0, 0, 170}),
	netip.AddrFrom4([4]byte{192, 0, 0, 171}),
}

var dns64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

// clatPrefix is the RFC 7335 IPv4 service-continuity prefix used by
// client-side translators (CLAT).
var clatPrefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 29)

type dns64State struct {
	mu          sync.Mutex
	checkedAt   time.Time
	active      bool         // network is v6-only, no CLAT, prefix known
	prefix      netip.Prefix // discovered NAT64 prefix (/96)
	discovering bool
	generation  uint64
}

// dns64NetworkClassFn is a seam for tests.
var dns64NetworkClassFn = currentDNS64NetworkClass

func addrFromNetAddr(a net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	nip, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return nip.Unmap(), true
}

// dns64NetworkClass classifies the host addressing state from interface
// addresses. Only IPv4 on the default-route interface counts as usable, so
// RFC1918 addresses owned by Docker, Parallels, VMware, and similar virtual
// interfaces do not disable DNS64. CLAT is detected across all interfaces.
func dns64NetworkClass(defaultRouteAddrs, allAddrs []net.Addr) (hasUsableIPv4, hasCLAT bool) {
	for _, a := range allAddrs {
		nip, ok := addrFromNetAddr(a)
		if !ok || !nip.Is4() {
			continue
		}
		if clatPrefix.Contains(nip) {
			hasCLAT = true
		}
	}
	for _, a := range defaultRouteAddrs {
		nip, ok := addrFromNetAddr(a)
		if !ok || !nip.Is4() || clatPrefix.Contains(nip) {
			continue
		}
		if nip.IsLoopback() || nip.IsLinkLocalUnicast() || nip.IsUnspecified() {
			continue
		}
		hasUsableIPv4 = true
	}
	return hasUsableIPv4, hasCLAT
}

func currentDNS64NetworkClass() (hasUsableIPv4, hasCLAT bool, err error) {
	defaultRouteInterface, err := netmon.DefaultRouteInterface()
	if err != nil {
		return false, false, err
	}
	iface, err := net.InterfaceByName(defaultRouteInterface)
	if err != nil {
		return false, false, err
	}
	defaultRouteAddrs, err := iface.Addrs()
	if err != nil {
		return false, false, err
	}
	allAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, false, err
	}
	hasUsableIPv4, hasCLAT = dns64NetworkClass(defaultRouteAddrs, allAddrs)
	return hasUsableIPv4, hasCLAT, nil
}

// nat64PrefixFromAnswer derives the NAT64 prefix from an ipv4only.arpa AAAA
// answer per RFC 7050: find an AAAA embedding a well-known IPv4 address in
// its last 4 bytes and take the leading /96.
func nat64PrefixFromAnswer(answer *dns.Msg) (netip.Prefix, bool) {
	if answer == nil {
		return netip.Prefix{}, false
	}
	for _, rr := range answer.Answer {
		aaaa, ok := rr.(*dns.AAAA)
		if !ok {
			continue
		}
		v6, ok := netip.AddrFromSlice(aaaa.AAAA.To16())
		if !ok || v6.Is4() {
			continue
		}
		b := v6.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		for _, wk := range rfc7050WellKnown {
			if embedded == wk {
				var p [16]byte
				copy(p[:12], b[:12])
				return netip.PrefixFrom(netip.AddrFrom16(p), 96), true
			}
		}
	}
	return netip.Prefix{}, false
}

// synthesizeAAAAFromA returns a copy of aAnswer converted into an AAAA
// answer for the original AAAA request: every A record is mapped into the
// NAT64 prefix; other records (CNAMEs etc.) are preserved.
func synthesizeAAAAFromA(req *dns.Msg, aAnswer *dns.Msg, prefix netip.Prefix) *dns.Msg {
	if aAnswer == nil {
		return nil
	}
	out := aAnswer.Copy()
	out.SetReply(req)
	out.Rcode = aAnswer.Rcode
	out.Compress = true
	answers := make([]dns.RR, 0, len(aAnswer.Answer))
	pb := prefix.Addr().As16()
	for _, rr := range aAnswer.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			// Preserve CNAME chain records unchanged.
			answers = append(answers, dns.Copy(rr))
			continue
		}
		v4 := a.A.To4()
		if v4 == nil {
			continue
		}
		v4Addr, ok := netip.AddrFromSlice(v4)
		if !ok || !v4Addr.IsGlobalUnicast() || (prefix == dns64WellKnownPrefix && v4Addr.IsPrivate()) {
			continue
		}
		var b [16]byte
		copy(b[:12], pb[:12])
		copy(b[12:], v4)
		aaaa := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   a.Hdr.Name,
				Rrtype: dns.TypeAAAA,
				Class:  a.Hdr.Class,
				Ttl:    a.Hdr.Ttl,
			},
			AAAA: net.IP(b[:]),
		}
		answers = append(answers, aaaa)
	}
	out.Answer = answers
	return out
}

// answerHasAAAA reports whether the answer section contains any AAAA record.
func answerHasAAAA(answer *dns.Msg) bool {
	if answer == nil {
		return false
	}
	for _, rr := range answer.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			return true
		}
	}
	return false
}

// dns64Eligible reports whether an answer qualifies for DNS64 synthesis:
// an AAAA query answered NOERROR with no AAAA records. NXDOMAIN and error
// rcodes are never synthesized (RFC 6147 §5.1.2: the name genuinely does
// not exist or the query failed).
func dns64Eligible(req, answer *dns.Msg) bool {
	if req == nil || answer == nil || len(req.Question) == 0 || req.CheckingDisabled {
		return false
	}
	if req.Question[0].Qtype != dns.TypeAAAA {
		return false
	}
	if answer.Rcode != dns.RcodeSuccess {
		return false
	}
	return !answerHasAAAA(answer)
}

// dns64Active reports whether synthesis should currently run, re-evaluating
// network class and (if needed) kicking off background prefix discovery at
// most every dns64RecheckInterval.
func (p *prog) dns64Active() bool {
	s := &p.dns64
	s.mu.Lock()
	if time.Since(s.checkedAt) < dns64RecheckInterval {
		active := s.active
		s.mu.Unlock()
		return active
	}
	s.checkedAt = time.Now()
	generation := s.generation
	s.mu.Unlock()

	hasV4, hasCLAT, err := dns64NetworkClassFn()
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return s.active
	}
	if err != nil {
		s.active = false
		return false
	}
	if hasV4 || hasCLAT {
		// Dual-stack or 464XLAT: the OS/CLAT handles IPv4 reachability;
		// synthesis would be unnecessary (and on CLAT networks, harmful —
		// real A records are preferable so traffic uses the CLAT).
		s.generation++
		s.active = false
		s.prefix = netip.Prefix{}
		s.discovering = false
		return false
	}
	s.active = s.prefix.IsValid()
	if !s.discovering {
		s.discovering = true
		generation := s.generation
		go p.discoverNAT64Prefix(generation)
	}
	return s.active
}

func (p *prog) activeDNS64Prefix() (netip.Prefix, bool) {
	if !p.dns64Active() {
		return netip.Prefix{}, false
	}
	p.dns64.mu.Lock()
	defer p.dns64.mu.Unlock()
	return p.dns64.prefix, p.dns64.prefix.IsValid()
}

func dns64CacheVariant(prefix netip.Prefix) string {
	return "dns64:" + prefix.String()
}

func dns64CacheKey(msg *dns.Msg, upstream string, prefix netip.Prefix) dnscache.Key {
	return dnscache.NewVariantKey(msg, upstream, dns64CacheVariant(prefix))
}

func (p *prog) resetDNS64State() {
	p.dns64.mu.Lock()
	p.dns64.generation++
	p.dns64.checkedAt = time.Time{}
	p.dns64.active = false
	p.dns64.prefix = netip.Prefix{}
	p.dns64.discovering = false
	p.dns64.mu.Unlock()
}

func dns64RouteStateChanged(delta *netmon.ChangeDelta) bool {
	if delta == nil || delta.Old == nil || delta.New == nil {
		return true
	}
	if delta.Old.DefaultRouteInterface != delta.New.DefaultRouteInterface ||
		delta.Old.HaveV4 != delta.New.HaveV4 || delta.Old.HaveV6 != delta.New.HaveV6 {
		return true
	}
	if dns64StateHasCLAT(delta.Old) != dns64StateHasCLAT(delta.New) {
		return true
	}
	iface := delta.New.DefaultRouteInterface
	oldPrefixes := delta.Old.InterfaceIPs[iface]
	newPrefixes := delta.New.InterfaceIPs[iface]
	if len(oldPrefixes) != len(newPrefixes) {
		return true
	}
	newPrefixSet := make(map[netip.Prefix]struct{}, len(newPrefixes))
	for _, prefix := range newPrefixes {
		newPrefixSet[prefix] = struct{}{}
	}
	for _, prefix := range oldPrefixes {
		if _, ok := newPrefixSet[prefix]; !ok {
			return true
		}
	}
	return false
}

func dns64StateHasCLAT(state *netmon.State) bool {
	for _, prefixes := range state.InterfaceIPs {
		for _, prefix := range prefixes {
			if clatPrefix.Contains(prefix.Addr().Unmap()) {
				return true
			}
		}
	}
	return false
}

func (p *prog) handleDNS64NetworkChange(delta *netmon.ChangeDelta, major bool) {
	if major || dns64RouteStateChanged(delta) {
		p.resetDNS64State()
	}
}

func (p *prog) storeDiscoveredNAT64Prefix(generation uint64, prefix netip.Prefix) bool {
	p.dns64.mu.Lock()
	defer p.dns64.mu.Unlock()
	if p.dns64.generation != generation {
		return false
	}
	p.dns64.prefix = prefix
	p.dns64.active = true
	p.dns64.checkedAt = time.Now()
	return true
}

// discoverNAT64Prefix resolves ipv4only.arpa AAAA through the OS-discovered
// resolvers (the network's own DNS64 resolver) and stores the derived
// prefix. Runs in the background; failures leave synthesis inactive until
// the next recheck window.
func (p *prog) discoverNAT64Prefix(generation uint64) {
	defer func() {
		p.dns64.mu.Lock()
		if p.dns64.generation == generation {
			p.dns64.discovering = false
		}
		p.dns64.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), dns64DiscoverTimeout)
	defer cancel()
	ctx = ctrld.LoggerCtx(ctx, mainLog.Load())

	msg := new(dns.Msg)
	msg.SetQuestion(dns64WellKnownName, dns.TypeAAAA)
	resolver, err := ctrld.NewResolver(ctx, osUpstreamConfig)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("dns64: could not create OS resolver for NAT64 discovery")
		return
	}
	answer, err := resolver.Resolve(ctx, msg)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msg("dns64: NAT64 prefix discovery query failed")
		return
	}
	prefix, ok := nat64PrefixFromAnswer(answer)
	if !ok {
		mainLog.Load().Debug().Msg("dns64: no NAT64 prefix present (not a DNS64 network)")
		return
	}
	if !p.storeDiscoveredNAT64Prefix(generation, prefix) {
		return
	}
	mainLog.Load().Info().Msgf("dns64: discovered NAT64 prefix %s; enabling AAAA synthesis for IPv6-only network without CLAT", prefix)
}

// maybeDNS64 applies DNS64 synthesis to an already-filtered answer when the
// network requires it. resolveA re-resolves the question as an A query
// through the same upstream that produced the answer.
func (p *prog) maybeDNS64(ctx context.Context, req *dns.Msg, answer *dns.Msg, resolveA func(*dns.Msg) *dns.Msg) (*dns.Msg, netip.Prefix) {
	if !dns64Eligible(req, answer) || !p.dns64Active() {
		return answer, netip.Prefix{}
	}
	p.dns64.mu.Lock()
	prefix := p.dns64.prefix
	generation := p.dns64.generation
	p.dns64.mu.Unlock()
	if !prefix.IsValid() {
		return answer, netip.Prefix{}
	}
	aReq := req.Copy()
	aReq.Question[0].Qtype = dns.TypeA
	aAnswer := resolveA(aReq)
	if aAnswer == nil || aAnswer.Rcode != dns.RcodeSuccess || !sameQuestion(aReq, aAnswer) {
		return answer, netip.Prefix{}
	}
	synth := synthesizeAAAAFromA(req, aAnswer, prefix)
	p.dns64.mu.Lock()
	current := p.dns64.active && p.dns64.generation == generation && p.dns64.prefix == prefix
	p.dns64.mu.Unlock()
	if !current {
		return answer, netip.Prefix{}
	}
	if synth == nil || !answerHasAAAA(synth) {
		// The companion A lookup completed successfully, so this passthrough
		// answer is definitive for the current prefix and may be cached in the
		// DNS64 variant to avoid repeating both upstream lookups.
		return answer, prefix
	}
	ctrld.Log(ctx, mainLog.Load().Debug(), "dns64: synthesized AAAA from A records via NAT64 prefix %s", prefix)
	return synth, prefix
}

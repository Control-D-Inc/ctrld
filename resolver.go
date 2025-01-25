package ctrld

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"io"

	"github.com/rs/zerolog"
	"github.com/miekg/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
)

const (
	// ResolverTypeDOH specifies DoH resolver.
	ResolverTypeDOH = "doh"
	// ResolverTypeDOH3 specifies DoH3 resolver.
	ResolverTypeDOH3 = "doh3"
	// ResolverTypeDOT specifies DoT resolver.
	ResolverTypeDOT = "dot"
	// ResolverTypeDOQ specifies DoQ resolver.
	ResolverTypeDOQ = "doq"
	// ResolverTypeOS specifies OS resolver.
	ResolverTypeOS = "os"
	// ResolverTypeLegacy specifies legacy resolver.
	ResolverTypeLegacy = "legacy"
	// ResolverTypePrivate is like ResolverTypeOS, but use for private resolver only.
	ResolverTypePrivate = "private"
	// ResolverTypeLocal is like ResolverTypeOS, but use for local resolver only.
	ResolverTypeLocal = "local"
	// ResolverTypeSDNS specifies resolver with information encoded using DNS Stamps.
	// See: https://dnscrypt.info/stamps-specifications/
	ResolverTypeSDNS = "sdns"
)

const (
	controldBootstrapDns = "76.76.2.22"
	controldPublicDns    = "76.76.2.0"
)

var controldPublicDnsWithPort = net.JoinHostPort(controldPublicDns, "53")

// or is the Resolver used for ResolverTypeOS.
var or = newResolverWithNameserver(defaultNameservers())

var localResolver = newLocalResolver()

func newLocalResolver() Resolver {
	var nss []string
	for _, addr := range Rfc1918Addresses() {
		nss = append(nss, net.JoinHostPort(addr, "53"))
	}
	return NewResolverWithNameserver(nss)
}

// LanQueryCtxKey is the context.Context key to indicate that the request is for LAN network.
type LanQueryCtxKey struct{}

// LanQueryCtx returns a context.Context with LanQueryCtxKey set.
func LanQueryCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, LanQueryCtxKey{}, true)
}

// defaultNameservers is like nameservers with each element formed "ip:53".
func defaultNameservers() []string {
	ns := nameservers()
	nss := make([]string, len(ns))
	for i := range ns {
		nss[i] = net.JoinHostPort(ns[i], "53")
	}
	return nss
}

// availableNameservers returns list of current available DNS servers of the system.
func availableNameservers() []string {
	var nss []string
	// Ignore local addresses to prevent loop.
	regularIPs, loopbackIPs, _ := netmon.LocalAddresses()
	machineIPsMap := make(map[string]struct{}, len(regularIPs))


	//load the logger
	logger := zerolog.New(io.Discard)
	if ProxyLogger.Load() != nil {
		logger = *ProxyLogger.Load()
	}
	Log(context.Background(), logger.Debug(),
		"Got local addresses - regular IPs: %v, loopback IPs: %v", regularIPs, loopbackIPs)

	for _, v := range slices.Concat(regularIPs, loopbackIPs) {
		ipStr := v.String()
		machineIPsMap[ipStr] = struct{}{}
		Log(context.Background(), logger.Debug(),
			"Added local IP to OS resolverexclusion map: %s", ipStr)
	}

	systemNameservers := nameservers()
	Log(context.Background(), logger.Debug(),
		"Got system nameservers: %v", systemNameservers)

	for _, ns := range systemNameservers {
		if _, ok := machineIPsMap[ns]; ok {
			Log(context.Background(), logger.Debug(),
				"Skipping local nameserver: %s", ns)
			continue
		}
		nss = append(nss, ns)
		Log(context.Background(), logger.Debug(),
			"Added non-local nameserver: %s", ns)
	}

	Log(context.Background(), logger.Debug(),
		"Final available nameservers: %v", nss)
	return nss
}

// InitializeOsResolver initializes OS resolver using the current system DNS settings.
// It returns the nameservers that is going to be used by the OS resolver.
//
// It's the caller's responsibility to ensure the system DNS is in a clean state before
// calling this function.
func InitializeOsResolver() []string {
	ns := initializeOsResolver(availableNameservers())
	return ns
}

// initializeOsResolver performs logic for choosing OS resolver nameserver.
// The logic:
//
// - First available LAN servers are saved and store.
// - Later calls, if no LAN servers available, the saved servers above will be used.
func initializeOsResolver(servers []string) []string {
	var lanNss, publicNss []string

	// First categorize servers
	for _, ns := range servers {
		addr, err := netip.ParseAddr(ns)
		if err != nil {
			continue
		}
		server := net.JoinHostPort(ns, "53")
		if isLanAddr(addr) {
			lanNss = append(lanNss, server)
		} else {
			publicNss = append(publicNss, server)
		}
	}

	// Store initial servers immediately
	if len(lanNss) > 0 {
		or.initializedLanServers.CompareAndSwap(nil, &lanNss)
		or.lanServers.Store(&lanNss)
	}

	if len(publicNss) == 0 {
		publicNss = []string{controldPublicDnsWithPort}
	}
	or.publicServers.Store(&publicNss)

	// no longer testing servers in the background
	// if DCHP nameservers are not working, this is outside of our control

	// // Test servers in background and remove failures
	// go func() {
	// 	// Test servers in parallel but maintain order
	// 	type result struct {
	// 		index  int
	// 		server string
	// 		valid  bool
	// 	}

	// 	testServers := func(servers []string) []string {
	// 		if len(servers) == 0 {
	// 			return nil
	// 		}

	// 		results := make(chan result, len(servers))
	// 		var wg sync.WaitGroup

	// 		for i, server := range servers {
	// 			wg.Add(1)
	// 			go func(idx int, s string) {
	// 				defer wg.Done()
	// 				results <- result{
	// 					index:  idx,
	// 					server: s,
	// 					valid:  testNameServerFn(s),
	// 				}
	// 			}(i, server)
	// 		}

	// 		go func() {
	// 			wg.Wait()
	// 			close(results)
	// 		}()

	// 		// Collect results maintaining original order
	// 		validServers := make([]string, 0, len(servers))
	// 		ordered := make([]result, 0, len(servers))
	// 		for r := range results {
	// 			ordered = append(ordered, r)
	// 		}
	// 		slices.SortFunc(ordered, func(a, b result) int {
	// 			return a.index - b.index
	// 		})
	// 		for _, r := range ordered {
	// 			if r.valid {
	// 				validServers = append(validServers, r.server)
	// 			} else {
	// 				ProxyLogger.Load().Debug().Str("nameserver", r.server).Msg("nameserver failed validation testing")
	// 			}
	// 		}
	// 		return validServers
	// 	}

	// 	// Test and update LAN servers
	// 	if validLanNss := testServers(lanNss); len(validLanNss) > 0 {
	// 		or.lanServers.Store(&validLanNss)
	// 	}

	// 	// Test and update public servers
	// 	validPublicNss := testServers(publicNss)
	// 	if len(validPublicNss) == 0 {
	// 		validPublicNss = []string{controldPublicDnsWithPort}
	// 	}
	// 	or.publicServers.Store(&validPublicNss)
	// }()

	return slices.Concat(lanNss, publicNss)
}

// // testNameserverFn sends a test query to DNS nameserver to check if the server is available.
// var testNameServerFn = testNameserver

// // testPlainDnsNameserver sends a test query to DNS nameserver to check if the server is available.
// func testNameserver(addr string) bool {
// 	// Skip link-local addresses without scope IDs and deprecated site-local addresses
// 	if ip, err := netip.ParseAddr(addr); err == nil {
// 		if ip.Is6() {
// 			if ip.IsLinkLocalUnicast() && !strings.Contains(addr, "%") {
// 				ProxyLogger.Load().Debug().
// 					Str("nameserver", addr).
// 					Msg("skipping link-local IPv6 address without scope ID")
// 				return false
// 			}
// 			// Skip deprecated site-local addresses (fec0::/10)
// 			if strings.HasPrefix(ip.String(), "fec0:") {
// 				ProxyLogger.Load().Debug().
// 					Str("nameserver", addr).
// 					Msg("skipping deprecated site-local IPv6 address")
// 				return false
// 			}
// 		}
// 	}

// 	ProxyLogger.Load().Debug().
// 		Str("input_addr", addr).
// 		Msg("testing nameserver")

// 	// Handle both IPv4 and IPv6 addresses
// 	serverAddr := addr
// 	host, port, err := net.SplitHostPort(addr)
// 	if err != nil {
// 		// No port in address, add default port 53
// 		serverAddr = net.JoinHostPort(addr, "53")
// 	} else if port == "" {
// 		// Has split markers but empty port
// 		serverAddr = net.JoinHostPort(host, "53")
// 	}

// 	ProxyLogger.Load().Debug().
// 		Str("server_addr", serverAddr).
// 		Msg("using server address")

// 	// Test domains that are likely to exist and respond quickly
// 	testDomains := []struct {
// 		name  string
// 		qtype uint16
// 	}{
// 		{".", dns.TypeNS},            // Root NS query - should always work
// 		{"controld.com.", dns.TypeA}, // Fallback to a reliable domain
// 	}

// 	client := &dns.Client{
// 		Timeout: 2 * time.Second,
// 		Net:     "udp",
// 	}

// 	// Try each test query until one succeeds
// 	for _, test := range testDomains {
// 		msg := new(dns.Msg)
// 		msg.SetQuestion(test.name, test.qtype)
// 		msg.RecursionDesired = true

// 		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
// 		resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
// 		cancel()

// 		if err == nil && resp != nil {
// 			return true
// 		}

// 		ProxyLogger.Load().Error().
// 			Err(err).
// 			Str("nameserver", serverAddr).
// 			Str("test_domain", test.name).
// 			Str("query_type", dns.TypeToString[test.qtype]).
// 			Msg("DNS availability test failed")
// 	}

// 	return false
// }

// Resolver is the interface that wraps the basic DNS operations.
//
// Resolve resolves the DNS query, return the result and the corresponding error.
type Resolver interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

var errUnknownResolver = errors.New("unknown resolver")

// NewResolver creates a Resolver based on the given upstream config.
func NewResolver(uc *UpstreamConfig) (Resolver, error) {
	typ := uc.Type
	switch typ {
	case ResolverTypeDOH, ResolverTypeDOH3:
		return newDohResolver(uc), nil
	case ResolverTypeDOT:
		return &dotResolver{uc: uc}, nil
	case ResolverTypeDOQ:
		return &doqResolver{uc: uc}, nil
	case ResolverTypeOS:
		return or, nil
	case ResolverTypeLegacy:
		return &legacyResolver{uc: uc}, nil
	case ResolverTypePrivate:
		return NewPrivateResolver(), nil
	case ResolverTypeLocal:
		return localResolver, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnknownResolver, typ)
}

type osResolver struct {
	initializedLanServers atomic.Pointer[[]string]
	lanServers            atomic.Pointer[[]string]
	publicServers         atomic.Pointer[[]string]
}

type osResolverResult struct {
	answer *dns.Msg
	err    error
	server string
	lan    bool
}

// Resolve resolves DNS queries using pre-configured nameservers.
// Query is sent to all nameservers concurrently, and the first
// success response will be returned.
func (o *osResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	publicServers := *o.publicServers.Load()
	var nss []string
	if p := o.lanServers.Load(); p != nil {
		nss = append(nss, (*p)...)
	}
	numServers := len(nss) + len(publicServers)
	// If this is a LAN query, skip public DNS.
	lan, ok := ctx.Value(LanQueryCtxKey{}).(bool)
	if ok && lan {
		numServers -= len(publicServers)
	}
	if numServers == 0 {
		return nil, errors.New("no nameservers available")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dnsClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	ch := make(chan *osResolverResult, numServers)
	wg := &sync.WaitGroup{}
	wg.Add(numServers)
	go func() {
		wg.Wait()
		close(ch)
	}()

	do := func(servers []string, isLan bool) {
		for _, server := range servers {
			go func(server string) {
				defer wg.Done()
				answer, _, err := dnsClient.ExchangeContext(ctx, msg.Copy(), server)
				ch <- &osResolverResult{answer: answer, err: err, server: server, lan: isLan}
			}(server)
		}
	}
	do(nss, true)
	if !lan {
		do(publicServers, false)
	}

	logAnswer := func(server string) {
		if before, _, found := strings.Cut(server, ":"); found {
			server = before
		}
		Log(ctx, ProxyLogger.Load().Debug(), "got answer from nameserver: %s", server)
	}
	var (
		nonSuccessAnswer      *dns.Msg
		nonSuccessServer      string
		controldSuccessAnswer *dns.Msg
		publicServerAnswer    *dns.Msg
		publicServer          string
	)
	errs := make([]error, 0, numServers)
	for res := range ch {
		switch {
		case res.answer != nil && res.answer.Rcode == dns.RcodeSuccess:
			switch {
			case res.server == controldPublicDnsWithPort:
				controldSuccessAnswer = res.answer
			case !res.lan && publicServerAnswer == nil:
				publicServerAnswer = res.answer
				publicServer = res.server
			default:
				Log(ctx, ProxyLogger.Load().Debug(), "got LAN answer from: %s", res.server)
				cancel()
				logAnswer(res.server)
				return res.answer, nil
			}
		case res.answer != nil:
			nonSuccessAnswer = res.answer
			nonSuccessServer = res.server
			Log(ctx, ProxyLogger.Load().Debug(), "got non-success answer from: %s with code: %d",
				res.server, res.answer.Rcode)
		}
		errs = append(errs, res.err)
	}
	if publicServerAnswer != nil {
		Log(ctx, ProxyLogger.Load().Debug(), "got public answer from: %s", publicServer)
		logAnswer(publicServer)
		return publicServerAnswer, nil
	}
	if controldSuccessAnswer != nil {
		Log(ctx, ProxyLogger.Load().Debug(), "got ControlD answer from: %s", controldPublicDnsWithPort)
		logAnswer(controldPublicDnsWithPort)
		return controldSuccessAnswer, nil
	}
	if nonSuccessAnswer != nil {
		Log(ctx, ProxyLogger.Load().Debug(), "got non-success answer from: %s", nonSuccessServer)
		logAnswer(nonSuccessServer)
		return nonSuccessAnswer, nil
	}
	return nil, errors.Join(errs...)
}

type legacyResolver struct {
	uc *UpstreamConfig
}

func (r *legacyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// See comment in (*dotResolver).resolve method.
	dialer := newDialer(net.JoinHostPort(controldBootstrapDns, "53"))
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	_, udpNet := r.uc.netForDNSType(dnsTyp)
	dnsClient := &dns.Client{
		Net:    udpNet,
		Dialer: dialer,
	}
	endpoint := r.uc.Endpoint
	if r.uc.BootstrapIP != "" {
		dnsClient.Net = "udp"
		_, port, _ := net.SplitHostPort(endpoint)
		endpoint = net.JoinHostPort(r.uc.BootstrapIP, port)
	}

	answer, _, err := dnsClient.ExchangeContext(ctx, msg, endpoint)
	return answer, err
}

type dummyResolver struct{}

func (d dummyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	ans := new(dns.Msg)
	ans.SetReply(msg)
	return ans, nil
}

// LookupIP looks up host using OS resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(domain string) []string {
	return lookupIP(domain, -1, true)
}

func lookupIP(domain string, timeout int, withBootstrapDNS bool) (ips []string) {
	nss := defaultNameservers()
	if withBootstrapDNS {
		nss = append([]string{net.JoinHostPort(controldBootstrapDns, "53")}, nss...)
	}
	resolver := newResolverWithNameserver(nss)
	ProxyLogger.Load().Debug().Msgf("resolving %q using bootstrap DNS %q", domain, nss)
	timeoutMs := 2000
	if timeout > 0 && timeout < timeoutMs {
		timeoutMs = timeout
	}
	questionDomain := dns.Fqdn(domain)

	// Getting the real target domain name from CNAME if presents.
	targetDomain := func(answers []dns.RR) string {
		for _, a := range answers {
			switch ar := a.(type) {
			case *dns.CNAME:
				return ar.Target
			}
		}
		return questionDomain
	}
	// Getting ip address from A or AAAA record.
	ipFromRecord := func(record dns.RR, target string) string {
		switch ar := record.(type) {
		case *dns.A:
			if ar.Hdr.Name != target || len(ar.A) == 0 {
				return ""
			}
			return ar.A.String()
		case *dns.AAAA:
			if ar.Hdr.Name != target || len(ar.AAAA) == 0 {
				return ""
			}
			return ar.AAAA.String()
		}
		return ""
	}

	lookup := func(dnsType uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
		m := new(dns.Msg)
		m.SetQuestion(questionDomain, dnsType)
		m.RecursionDesired = true

		r, err := resolver.Resolve(ctx, m)
		if err != nil {
			ProxyLogger.Load().Error().Err(err).Msgf("could not lookup %q record for domain %q", dns.TypeToString[dnsType], domain)
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			ProxyLogger.Load().Error().Msgf("could not resolve domain %q, return code: %s", domain, dns.RcodeToString[r.Rcode])
			return
		}
		if len(r.Answer) == 0 {
			ProxyLogger.Load().Error().Msg("no answer from OS resolver")
			return
		}
		target := targetDomain(r.Answer)
		for _, a := range r.Answer {
			if ip := ipFromRecord(a, target); ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	// Find all A, AAAA records of the domain.
	for _, dnsType := range []uint16{dns.TypeAAAA, dns.TypeA} {
		lookup(dnsType)
	}
	return ips
}

// NewBootstrapResolver returns an OS resolver, which use following nameservers:
//
//   - Gateway IP address (depends on OS).
//   - Input servers.
func NewBootstrapResolver(servers ...string) Resolver {
	nss := defaultNameservers()
	nss = append([]string{controldPublicDnsWithPort}, nss...)
	for _, ns := range servers {
		nss = append([]string{net.JoinHostPort(ns, "53")}, nss...)
	}
	return NewResolverWithNameserver(nss)
}

// NewPrivateResolver returns an OS resolver, which includes only private DNS servers,
// excluding:
//
// - Nameservers from /etc/resolv.conf file.
// - Nameservers which is local RFC1918 addresses.
//
// This is useful for doing PTR lookup in LAN network.
func NewPrivateResolver() Resolver {
	nss := defaultNameservers()
	resolveConfNss := nameserversFromResolvconf()
	localRfc1918Addrs := Rfc1918Addresses()
	n := 0
	for _, ns := range nss {
		host, _, _ := net.SplitHostPort(ns)
		// Ignore nameserver from resolve.conf file, because the nameserver can be either:
		//
		//  - ctrld itself.
		//  - Direct listener that has ctrld as an upstream (e.g: dnsmasq).
		//
		// causing the query always succeed.
		if slices.Contains(resolveConfNss, host) {
			continue
		}
		// Ignoring local RFC 1918 addresses.
		if slices.Contains(localRfc1918Addrs, host) {
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
			nss[n] = ns
			n++
		}
	}
	nss = nss[:n]
	return newResolverWithNameserver(nss)
}

// NewResolverWithNameserver returns a Resolver which uses the given nameservers
// for resolving DNS queries. If nameservers is empty, a dummy resolver will be returned.
//
// Each nameserver must be form "host:port". It's the caller responsibility to ensure all
// nameservers are well formatted by using net.JoinHostPort function.
func NewResolverWithNameserver(nameservers []string) Resolver {
	if len(nameservers) == 0 {
		return &dummyResolver{}
	}
	return newResolverWithNameserver(nameservers)
}

// newResolverWithNameserver returns an OS resolver from given nameservers list.
// The caller must ensure each server in list is formed "ip:53".
func newResolverWithNameserver(nameservers []string) *osResolver {
	r := &osResolver{}
	var publicNss []string
	var lanNss []string
	for _, ns := range slices.Sorted(slices.Values(nameservers)) {
		ip, _, _ := net.SplitHostPort(ns)
		addr, _ := netip.ParseAddr(ip)
		if isLanAddr(addr) {
			lanNss = append(lanNss, ns)
		} else {
			publicNss = append(publicNss, ns)
		}
	}
	r.lanServers.Store(&lanNss)
	r.publicServers.Store(&publicNss)
	return r
}

// Rfc1918Addresses returns the list of local interfaces private IP addresses
func Rfc1918Addresses() []string {
	var res []string
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || !ipNet.IP.IsPrivate() {
				continue
			}
			res = append(res, ipNet.IP.String())
		}
	})
	return res
}

func newDialer(dnsAddress string) *net.Dialer {
	return &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, dnsAddress)
			},
		},
	}
}

// isLanAddr reports whether addr is considered a LAN ip address.
func isLanAddr(addr netip.Addr) bool {
	return addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		tsaddr.CGNATRange().Contains(addr)
}

package ctrld

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
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
	// ResolverTypeSDNS specifies resolver with information encoded using DNS Stamps.
	// See: https://dnscrypt.info/stamps-specifications/
	ResolverTypeSDNS = "sdns"
)

const controldPublicDns = "76.76.2.0"

var controldPublicDnsWithPort = net.JoinHostPort(controldPublicDns, "53")

var (
	resolverMutex    sync.Mutex
	or               *osResolver
	defaultLocalIPv4 atomic.Value // holds net.IP (IPv4)
	defaultLocalIPv6 atomic.Value // holds net.IP (IPv6)
)

// LanQueryCtxKey is the context.Context key to indicate that the request is for LAN network.
type LanQueryCtxKey struct{}

// LanQueryCtx returns a context.Context with LanQueryCtxKey set.
func LanQueryCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, LanQueryCtxKey{}, true)
}

// defaultNameservers is like nameservers with each element formed "ip:53".
func defaultNameservers(ctx context.Context) []string {
	ns := nameservers(ctx)
	nss := make([]string, len(ns))
	for i := range ns {
		nss[i] = net.JoinHostPort(ns[i], "53")
	}
	return nss
}

// availableNameservers returns list of current available DNS servers of the system.
func availableNameservers(ctx context.Context) []string {
	var nss []string
	// Ignore local addresses to prevent loop.
	regularIPs, loopbackIPs, _ := netmon.LocalAddresses()
	machineIPsMap := make(map[string]struct{}, len(regularIPs))

	// Load the logger.
	logger := LoggerFromCtx(ctx)
	logger.Debug().Msgf("Got local addresses - regular IPs: %v, loopback IPs: %v", regularIPs, loopbackIPs)

	for _, v := range slices.Concat(regularIPs, loopbackIPs) {
		ipStr := v.String()
		machineIPsMap[ipStr] = struct{}{}
		logger.Debug().Msgf("Added local IP to OS resolverexclusion map: %s", ipStr)
	}

	systemNameservers := nameservers(ctx)
	logger.Debug().Msgf("Got system nameservers: %v", systemNameservers)

	for _, ns := range systemNameservers {
		if _, ok := machineIPsMap[ns]; ok {
			logger.Debug().Msgf("Skipping local nameserver: %s", ns)
			continue
		}
		nss = append(nss, ns)
		logger.Debug().Msgf("Added non-local nameserver: %s", ns)
	}

	logger.Debug().Msgf("Final available nameservers: %v", nss)

	return nss
}

// InitializeOsResolver initializes OS resolver using the current system DNS settings.
// It returns the nameservers that is going to be used by the OS resolver.
//
// It's the caller's responsibility to ensure the system DNS is in a clean state before
// calling this function.
func InitializeOsResolver(ctx context.Context, guardAgainstNoNameservers bool) []string {
	nameservers := availableNameservers(ctx)
	// if no nameservers, return empty slice so we dont remove all nameservers
	if len(nameservers) == 0 && guardAgainstNoNameservers {
		return []string{}
	}
	ns := initializeOsResolver(nameservers)
	resolverMutex.Lock()
	defer resolverMutex.Unlock()
	or = newResolverWithNameserver(ns)
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

	if len(publicNss) == 0 {
		publicNss = []string{controldPublicDnsWithPort}
	}

	return slices.Concat(lanNss, publicNss)
}

// Resolver is the interface that wraps the basic DNS operations.
//
// Resolve resolves the DNS query, return the result and the corresponding error.
type Resolver interface {
	Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

var errUnknownResolver = errors.New("unknown resolver")

// NewResolver creates a Resolver based on the given upstream config.
func NewResolver(ctx context.Context, uc *UpstreamConfig) (Resolver, error) {
	typ := uc.Type
	switch typ {
	case ResolverTypeDOH, ResolverTypeDOH3:
		return newDohResolver(uc), nil
	case ResolverTypeDOT:
		return &dotResolver{uc: uc}, nil
	case ResolverTypeDOQ:
		return &doqResolver{uc: uc}, nil
	case ResolverTypeOS:
		resolverMutex.Lock()
		if or == nil {
			logger := LoggerFromCtx(ctx)
			logger.Debug().Msgf("Initialize new OS resolver")
			or = newResolverWithNameserver(defaultNameservers(ctx))
		}
		resolverMutex.Unlock()
		return or, nil
	case ResolverTypeLegacy:
		return &legacyResolver{uc: uc}, nil
	case ResolverTypePrivate:
		return NewPrivateResolver(ctx), nil
	}
	return nil, fmt.Errorf("%w: %s", errUnknownResolver, typ)
}

type osResolver struct {
	lanServers    atomic.Pointer[[]string]
	publicServers atomic.Pointer[[]string]
	group         *singleflight.Group
	cache         *sync.Map
}

type osResolverResult struct {
	answer *dns.Msg
	err    error
	server string
	lan    bool
}

type publicResponse struct {
	answer *dns.Msg
	server string
}

// SetDefaultLocalIPv4 updates the stored local IPv4.
func SetDefaultLocalIPv4(ctx context.Context, ip net.IP) {
	logger := LoggerFromCtx(ctx)
	logger.Debug().Msgf("SetDefaultLocalIPv4: %s", ip)
	defaultLocalIPv4.Store(ip)
}

// SetDefaultLocalIPv6 updates the stored local IPv6.
func SetDefaultLocalIPv6(ctx context.Context, ip net.IP) {
	logger := LoggerFromCtx(ctx)
	logger.Debug().Msgf("SetDefaultLocalIPv6: %s", ip)
	defaultLocalIPv6.Store(ip)
}

// GetDefaultLocalIPv4 returns the stored local IPv4 or nil if none.
func GetDefaultLocalIPv4() net.IP {
	if v := defaultLocalIPv4.Load(); v != nil {
		return v.(net.IP)
	}
	return nil
}

// GetDefaultLocalIPv6 returns the stored local IPv6 or nil if none.
func GetDefaultLocalIPv6() net.IP {
	if v := defaultLocalIPv6.Load(); v != nil {
		return v.(net.IP)
	}
	return nil
}

// customDNSExchange wraps the DNS exchange to use our debug dialer.
// It uses dns.ExchangeWithConn so that our custom dialer is used directly.
func customDNSExchange(ctx context.Context, msg *dns.Msg, server string, desiredLocalIP net.IP) (*dns.Msg, time.Duration, error) {
	baseDialer := &net.Dialer{
		Timeout:  3 * time.Second,
		Resolver: &net.Resolver{PreferGo: true},
	}
	if desiredLocalIP != nil {
		baseDialer.LocalAddr = &net.UDPAddr{IP: desiredLocalIP, Port: 0}
	}
	dnsClient := &dns.Client{Net: "udp"}
	dnsClient.Dialer = baseDialer
	return dnsClient.ExchangeContext(ctx, msg, server)
}

const hotCacheTTL = time.Second

// Resolve resolves DNS queries using pre-configured nameservers.
// The Query is sent to all nameservers concurrently, and the first
// success response will be returned.
//
// To guard against unexpected DoS to upstreams, multiple queries of
// the same Qtype to a domain will be shared, so there's only 1 qps
// for each upstream at any time.
//
// Further, a hot cache will be used, so repeated queries will be cached
// for a short period (currently 1 second), reducing unnecessary traffics
// sent to upstreams.
func (o *osResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("no question found")
	}
	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	qtype := msg.Question[0].Qtype

	// Unique key for the singleflight group.
	key := fmt.Sprintf("%s:%d:", domain, qtype)

	logger := LoggerFromCtx(ctx)
	// Checking the cache first.
	if val, ok := o.cache.Load(key); ok {
		if val, ok := val.(*dns.Msg); ok {
			Log(ctx, logger.Debug(), "hit hot cached result: %s - %s", domain, dns.TypeToString[qtype])
			res := val.Copy()
			SetCacheReply(res, msg, val.Rcode)
			return res, nil
		}
	}

	// Ensure only one DNS query is in flight for the key.
	v, err, shared := o.group.Do(key, func() (interface{}, error) {
		msg, err := o.resolve(ctx, msg)
		if err != nil {
			return nil, err
		}
		// If we got an answer, storing it to the hot cache for hotCacheTTL
		// This prevents possible DoS to upstream, ensuring there's only 1 QPS.
		o.cache.Store(key, msg)
		// Depends on go runtime scheduling, the result may end up in hot cache longer
		// than hotCacheTTL duration. However, this is fine since we only want to guard
		// against DoS attack. The result will be cleaned from the cache eventually.
		time.AfterFunc(hotCacheTTL, func() {
			o.removeCache(key)
		})
		return msg, nil
	})
	if err != nil {
		return nil, err
	}

	sharedMsg, ok := v.(*dns.Msg)
	if !ok {
		return nil, fmt.Errorf("invalid answer for key: %s", key)
	}
	res := sharedMsg.Copy()
	SetCacheReply(res, msg, sharedMsg.Rcode)
	if shared {
		Log(ctx, logger.Debug(), "shared result: %s - %s", domain, dns.TypeToString[qtype])
	}

	return res, nil
}

// resolve sends the query to current nameservers.
func (o *osResolver) resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	publicServers := *o.publicServers.Load()
	var nss []string
	if p := o.lanServers.Load(); p != nil {
		nss = append(nss, (*p)...)
	}
	numServers := len(nss) + len(publicServers)

	// If this is a LAN query, skip public DNS.
	lan, ok := ctx.Value(LanQueryCtxKey{}).(bool)

	// remove controldPublicDnsWithPort from publicServers for LAN queries
	// this is to prevent DoS for high frequency local requests
	if ok && lan {
		if index := slices.Index(publicServers, controldPublicDnsWithPort); index != -1 {
			publicServers = slices.Delete(publicServers, index, index+1)
			numServers--
		}
	}
	question := ""
	if msg != nil && len(msg.Question) > 0 {
		question = msg.Question[0].Name
	}
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "os resolver query for %s with nameservers: %v public: %v", question, nss, publicServers)

	// New check: If no resolvers are available, return an error.
	if numServers == 0 {
		return nil, errors.New("no nameservers available for query")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
				var answer *dns.Msg
				var err error
				var localOSResolverIP net.IP
				if runtime.GOOS == "darwin" {
					host, _, err := net.SplitHostPort(server)
					if err == nil {
						ip := net.ParseIP(host)
						if ip != nil && ip.To4() == nil {
							// IPv6 nameserver; use default IPv6 address (if set)
							localOSResolverIP = GetDefaultLocalIPv6()
						} else {
							localOSResolverIP = GetDefaultLocalIPv4()
						}
					}
				}
				answer, _, err = customDNSExchange(ctx, msg.Copy(), server, localOSResolverIP)
				ch <- &osResolverResult{answer: answer, err: err, server: server, lan: isLan}
			}(server)
		}
	}

	logAnswer := func(server string) {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			// If splitting fails, fallback to the original server string
			host = server
		}
		Log(ctx, logger.Debug(), "got answer from nameserver: %s", host)
	}

	// try local nameservers
	if len(nss) > 0 {
		do(nss, true)
	}

	// we must always try the public servers too, since DCHP may have only public servers
	// this is okay to do since we always prefer LAN nameserver responses
	if len(publicServers) > 0 {
		do(publicServers, false)
	}

	var (
		nonSuccessAnswer      *dns.Msg
		nonSuccessServer      string
		controldSuccessAnswer *dns.Msg
		publicResponses       []publicResponse
	)
	errs := make([]error, 0, numServers)
	for res := range ch {
		switch {
		case res.answer != nil && res.answer.Rcode == dns.RcodeSuccess:
			switch {
			case res.lan:
				// Always prefer LAN responses immediately
				Log(ctx, logger.Debug(), "using LAN answer from: %s", res.server)
				cancel()
				logAnswer(res.server)
				return res.answer, nil
			case res.server == controldPublicDnsWithPort:
				controldSuccessAnswer = res.answer
			case !res.lan:
				// if there are no LAN nameservers, we should not wait
				// just use the first response
				if len(nss) == 0 {
					Log(ctx, logger.Debug(), "using public answer from: %s", res.server)
					cancel()
					logAnswer(res.server)
					return res.answer, nil
				}
				publicResponses = append(publicResponses, publicResponse{
					answer: res.answer,
					server: res.server,
				})
			}
		case res.answer != nil:
			Log(ctx, logger.Debug(), "got non-success answer from: %s with code: %d",
				res.server, res.answer.Rcode)
			// When there are no LAN nameservers, we should not wait
			// for other nameservers to respond.
			if len(nss) == 0 {
				Log(ctx, logger.Debug(), "no lan nameservers using public non success answer")
				cancel()
				logAnswer(res.server)
				return res.answer, nil
			}
			nonSuccessAnswer = res.answer
			nonSuccessServer = res.server
		}
		errs = append(errs, res.err)
	}

	if len(publicResponses) > 0 {
		resp := publicResponses[0]
		Log(ctx, logger.Debug(), "using public answer from: %s", resp.server)
		logAnswer(resp.server)
		return resp.answer, nil
	}
	if controldSuccessAnswer != nil {
		Log(ctx, logger.Debug(), "using ControlD answer from: %s", controldPublicDnsWithPort)
		logAnswer(controldPublicDnsWithPort)
		return controldSuccessAnswer, nil
	}
	if nonSuccessAnswer != nil {
		Log(ctx, logger.Debug(), "using non-success answer from: %s", nonSuccessServer)
		logAnswer(nonSuccessServer)
		return nonSuccessAnswer, nil
	}
	return nil, errors.Join(errs...)
}

func (o *osResolver) removeCache(key string) {
	o.cache.Delete(key)
}

type legacyResolver struct {
	uc *UpstreamConfig
}

func (r *legacyResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// See comment in (*dotResolver).resolve method.
	dialer := newDialer(net.JoinHostPort(controldPublicDns, "53"))
	dnsTyp := uint16(0)
	if msg != nil && len(msg.Question) > 0 {
		dnsTyp = msg.Question[0].Qtype
	}
	_, udpNet := r.uc.netForDNSType(ctx, dnsTyp)
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

// LookupIP looks up domain using current system nameservers settings.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(ctx context.Context, domain string) []string {
	nss := initDefaultOsResolver(ctx)
	return lookupIP(ctx, domain, -1, nss)
}

// initDefaultOsResolver initializes the default OS resolver with system's default nameservers if it hasn't been initialized yet.
// It returns the combined list of LAN and public nameservers currently held by the resolver.
func initDefaultOsResolver(ctx context.Context) []string {
	logger := LoggerFromCtx(ctx)
	resolverMutex.Lock()
	defer resolverMutex.Unlock()
	if or == nil {
		logger.Debug().Msgf("Initialize new OS resolver with default nameservers")
		or = newResolverWithNameserver(defaultNameservers(ctx))
	}
	nss := *or.lanServers.Load()
	nss = append(nss, *or.publicServers.Load()...)
	return nss

}

// lookupIP looks up domain with given timeout and bootstrapDNS.
// If the timeout is negative, default timeout 2000 ms will be used.
// It returns nil if bootstrapDNS is nil or empty.
func lookupIP(ctx context.Context, domain string, timeout int, bootstrapDNS []string) (ips []string) {
	if net.ParseIP(domain) != nil {
		return []string{domain}
	}
	logger := LoggerFromCtx(ctx)
	if bootstrapDNS == nil {
		logger.Debug().Msgf("empty bootstrap DNS")
		return nil
	}

	resolver := newResolverWithNameserver(bootstrapDNS)
	logger.Debug().Msgf("resolving %q using bootstrap DNS %q", domain, bootstrapDNS)

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
			logger.Error().Err(err).Msgf("could not lookup %q record for domain %q", dns.TypeToString[dnsType], domain)
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			logger.Error().Msgf("could not resolve domain %q, return code: %s", domain, dns.RcodeToString[r.Rcode])
			return
		}
		if len(r.Answer) == 0 {
			logger.Error().Msg("no answer from OS resolver")
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

// NewPrivateResolver returns an OS resolver, which includes only private DNS servers,
// excluding:
//
// - Nameservers from /etc/resolv.conf file.
// - Nameservers which is local RFC1918 addresses.
//
// This is useful for doing PTR lookup in LAN network.
func NewPrivateResolver(ctx context.Context) Resolver {
	nss := initDefaultOsResolver(ctx)
	resolveConfNss := CurrentNameserversFromResolvconf()
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
	r := &osResolver{
		group: &singleflight.Group{},
		cache: &sync.Map{},
	}
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

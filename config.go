package ctrld

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/go-playground/validator/v10"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/tsaddr"

	"github.com/Control-D-Inc/ctrld/internal/dnsrcode"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// IpStackBoth ...
const (
	// IpStackBoth indicates that ctrld will use either ipv4 or ipv6 for connecting to upstream,
	// depending on which stack is available when receiving the DNS query.
	IpStackBoth = "both"
	// IpStackV4 indicates that ctrld will use only ipv4 for connecting to upstream.
	IpStackV4 = "v4"
	// IpStackV6 indicates that ctrld will use only ipv6 for connecting to upstream.
	IpStackV6 = "v6"
	// IpStackSplit indicates that ctrld will use either ipv4 or ipv6 for connecting to upstream,
	// depending on the record type of the DNS query.
	IpStackSplit = "split"

	// FreeDnsDomain is the domain name of free ControlD service.
	FreeDnsDomain = "freedns.controld.com"
	// FreeDNSBoostrapIP is the IP address of freedns.controld.com.
	FreeDNSBoostrapIP = "76.76.2.11"
	// FreeDNSBoostrapIPv6 is the IPv6 address of freedns.controld.com.
	FreeDNSBoostrapIPv6 = "2606:1a40::11"
	// PremiumDnsDomain is the domain name of premium ControlD service.
	PremiumDnsDomain = "dns.controld.com"
	// PremiumDNSBoostrapIP is the IP address of dns.controld.com.
	PremiumDNSBoostrapIP = "76.76.2.22"
	// PremiumDNSBoostrapIPv6 is the IPv6 address of dns.controld.com.
	PremiumDNSBoostrapIPv6 = "2606:1a40::22"

	// freeDnsDomainDev is the domain name of free ControlD service on dev env.
	freeDnsDomainDev = "freedns.controld.dev"
	// freeDNSBoostrapIP is the IP address of freedns.controld.dev.
	freeDNSBoostrapIP = "176.125.239.11"
	// freeDNSBoostrapIPv6 is the IPv6 address of freedns.controld.com.
	freeDNSBoostrapIPv6 = "2606:1a40:f000::11"
	// premiumDnsDomainDev is the domain name of premium ControlD service on dev env.
	premiumDnsDomainDev = "dns.controld.dev"
	// premiumDNSBoostrapIP is the IP address of dns.controld.dev.
	premiumDNSBoostrapIP = "176.125.239.22"
	// premiumDNSBoostrapIPv6 is the IPv6 address of dns.controld.dev.
	premiumDNSBoostrapIPv6 = "2606:1a40:f000::22"

	controlDComDomain = "controld.com"
	controlDNetDomain = "controld.net"
	controlDDevDomain = "controld.dev"

	endpointPrefixHTTPS = "https://"
	endpointPrefixQUIC  = "quic://"
	endpointPrefixH3    = "h3://"
	endpointPrefixSdns  = "sdns://"
)

var (
	controldParentDomains  = []string{controlDComDomain, controlDNetDomain, controlDDevDomain}
	controldVerifiedDomain = map[string]string{
		controlDComDomain: "verify.controld.com",
		controlDDevDomain: "verify.controld.dev",
	}
)

// SetConfigName set the config name that ctrld will look for.
// DEPRECATED: use SetConfigNameWithPath instead.
func SetConfigName(v *viper.Viper, name string) {
	configPath := "$HOME"
	// viper has its own way to get user home directory:  https://github.com/spf13/viper/blob/v1.14.0/util.go#L134
	// To be consistent, we prefer os.UserHomeDir instead.
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath = homeDir
	}
	SetConfigNameWithPath(v, name, configPath)
}

// SetConfigNameWithPath set the config path and name that ctrld will look for.
func SetConfigNameWithPath(v *viper.Viper, name, configPath string) {
	v.SetConfigName(name)
	v.AddConfigPath(configPath)
	v.AddConfigPath(".")
}

// InitConfig initializes default config values for given *viper.Viper instance.
func InitConfig(v *viper.Viper, name string) {
	v.SetDefault("listener", map[string]*ListenerConfig{
		"0": {
			IP:   "",
			Port: 0,
			Policy: &ListenerPolicyConfig{
				Name: "Main Policy",
				Networks: []Rule{
					{"network.0": []string{"upstream.0"}},
				},
				Rules: []Rule{
					{"example.com": []string{"upstream.0"}},
					{"*.ads.com": []string{"upstream.1"}},
				},
			},
		},
	})
	v.SetDefault("network", map[string]*NetworkConfig{
		"0": {
			Name:  "Network 0",
			Cidrs: []string{"0.0.0.0/0"},
		},
	})
	v.SetDefault("upstream", map[string]*UpstreamConfig{
		"0": {
			BootstrapIP: FreeDNSBoostrapIP,
			Name:        "Control D - Anti-Malware",
			Type:        ResolverTypeDOH,
			Endpoint:    "https://freedns.controld.com/p1",
			Timeout:     5000,
		},
		"1": {
			BootstrapIP: FreeDNSBoostrapIP,
			Name:        "Control D - No Ads",
			Type:        ResolverTypeDOQ,
			Endpoint:    "p2.freedns.controld.com",
			Timeout:     3000,
		},
	})
}

// Config represents ctrld supported configuration.
type Config struct {
	Service  ServiceConfig              `mapstructure:"service" toml:"service,omitempty"`
	Listener map[string]*ListenerConfig `mapstructure:"listener" toml:"listener" validate:"min=1,dive"`
	Network  map[string]*NetworkConfig  `mapstructure:"network" toml:"network" validate:"min=1,dive"`
	Upstream map[string]*UpstreamConfig `mapstructure:"upstream" toml:"upstream" validate:"min=1,dive"`
}

// HasUpstreamSendClientInfo reports whether the config has any upstream
// is configured to send client info to Control D DNS server.
func (c *Config) HasUpstreamSendClientInfo() bool {
	for _, uc := range c.Upstream {
		if uc.UpstreamSendClientInfo() {
			return true
		}
	}
	return false
}

// FirstListener returns the first listener config of current config. Listeners are sorted numerically.
//
// It panics if Config has no listeners configured.
func (c *Config) FirstListener() *ListenerConfig {
	listeners := make([]int, 0, len(c.Listener))
	for k := range c.Listener {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		listeners = append(listeners, n)
	}
	if len(listeners) == 0 {
		panic("missing listener config")
	}
	sort.Ints(listeners)
	return c.Listener[strconv.Itoa(listeners[0])]
}

// FirstUpstream returns the first upstream of current config. Upstreams are sorted numerically.
//
// It panics if Config has no upstreams configured.
func (c *Config) FirstUpstream() *UpstreamConfig {
	upstreams := make([]int, 0, len(c.Upstream))
	for k := range c.Upstream {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		upstreams = append(upstreams, n)
	}
	if len(upstreams) == 0 {
		panic("missing listener config")
	}
	sort.Ints(upstreams)
	return c.Upstream[strconv.Itoa(upstreams[0])]
}

// ServiceConfig specifies the general ctrld config.
type ServiceConfig struct {
	LogLevel                string         `mapstructure:"log_level" toml:"log_level,omitempty"`
	LogPath                 string         `mapstructure:"log_path" toml:"log_path,omitempty"`
	CacheEnable             bool           `mapstructure:"cache_enable" toml:"cache_enable,omitempty"`
	CacheSize               int            `mapstructure:"cache_size" toml:"cache_size,omitempty"`
	CacheTTLOverride        int            `mapstructure:"cache_ttl_override" toml:"cache_ttl_override,omitempty"`
	CacheServeStale         bool           `mapstructure:"cache_serve_stale" toml:"cache_serve_stale,omitempty"`
	CacheFlushDomains       []string       `mapstructure:"cache_flush_domains" toml:"cache_flush_domains" validate:"max=256"`
	MaxConcurrentRequests   *int           `mapstructure:"max_concurrent_requests" toml:"max_concurrent_requests,omitempty" validate:"omitempty,gte=0"`
	DHCPLeaseFile           string         `mapstructure:"dhcp_lease_file_path" toml:"dhcp_lease_file_path" validate:"omitempty,file"`
	DHCPLeaseFileFormat     string         `mapstructure:"dhcp_lease_file_format" toml:"dhcp_lease_file_format" validate:"required_unless=DHCPLeaseFile '',omitempty,oneof=dnsmasq isc-dhcp kea-dhcp4"`
	DiscoverMDNS            *bool          `mapstructure:"discover_mdns" toml:"discover_mdns,omitempty"`
	DiscoverARP             *bool          `mapstructure:"discover_arp" toml:"discover_arp,omitempty"`
	DiscoverDHCP            *bool          `mapstructure:"discover_dhcp" toml:"discover_dhcp,omitempty"`
	DiscoverPtr             *bool          `mapstructure:"discover_ptr" toml:"discover_ptr,omitempty"`
	DiscoverHosts           *bool          `mapstructure:"discover_hosts" toml:"discover_hosts,omitempty"`
	DiscoverRefreshInterval int            `mapstructure:"discover_refresh_interval" toml:"discover_refresh_interval,omitempty"`
	ClientIDPref            string         `mapstructure:"client_id_preference" toml:"client_id_preference,omitempty" validate:"omitempty,oneof=host mac"`
	MetricsQueryStats       bool           `mapstructure:"metrics_query_stats" toml:"metrics_query_stats,omitempty"`
	MetricsListener         string         `mapstructure:"metrics_listener" toml:"metrics_listener,omitempty"`
	DnsWatchdogEnabled      *bool          `mapstructure:"dns_watchdog_enabled" toml:"dns_watchdog_enabled,omitempty"`
	DnsWatchdogInvterval    *time.Duration `mapstructure:"dns_watchdog_interval" toml:"dns_watchdog_interval,omitempty"`
	RefetchTime             *int           `mapstructure:"refetch_time" toml:"refetch_time,omitempty"`
	ForceRefetchWaitTime    *int           `mapstructure:"force_refetch_wait_time" toml:"force_refetch_wait_time,omitempty"`
	LeakOnUpstreamFailure   *bool          `mapstructure:"leak_on_upstream_failure" toml:"leak_on_upstream_failure,omitempty"`
	Daemon                  bool           `mapstructure:"-" toml:"-"`
	AllocateIP              bool           `mapstructure:"-" toml:"-"`
}

// NetworkConfig specifies configuration for networks where ctrld will handle requests.
type NetworkConfig struct {
	Name   string       `mapstructure:"name" toml:"name,omitempty"`
	Cidrs  []string     `mapstructure:"cidrs" toml:"cidrs,omitempty" validate:"dive,cidr"`
	IPNets []*net.IPNet `mapstructure:"-" toml:"-"`
}

// UpstreamConfig specifies configuration for upstreams that ctrld will forward requests to.
type UpstreamConfig struct {
	Name        string `mapstructure:"name" toml:"name,omitempty"`
	Type        string `mapstructure:"type" toml:"type,omitempty" validate:"oneof=doh doh3 dot doq os legacy sdns ''"`
	Endpoint    string `mapstructure:"endpoint" toml:"endpoint,omitempty"`
	BootstrapIP string `mapstructure:"bootstrap_ip" toml:"bootstrap_ip,omitempty"`
	Domain      string `mapstructure:"-" toml:"-"`
	IPStack     string `mapstructure:"ip_stack" toml:"ip_stack,omitempty" validate:"ipstack"`
	Timeout     int    `mapstructure:"timeout" toml:"timeout,omitempty" validate:"gte=0"`
	// The caller should not access this field directly.
	// Use UpstreamSendClientInfo instead.
	SendClientInfo *bool `mapstructure:"send_client_info" toml:"send_client_info,omitempty"`
	// The caller should not access this field directly.
	// Use IsDiscoverable instead.
	Discoverable *bool `mapstructure:"discoverable" toml:"discoverable"`

	g                  singleflight.Group
	rebootstrap        atomic.Bool
	bootstrapIPs       []string
	bootstrapIPs4      []string
	bootstrapIPs6      []string
	transport          *http.Transport
	transportOnce      sync.Once
	transport4         *http.Transport
	transport6         *http.Transport
	http3RoundTripper  http.RoundTripper
	http3RoundTripper4 http.RoundTripper
	http3RoundTripper6 http.RoundTripper
	certPool           *x509.CertPool
	u                  *url.URL
	fallbackOnce       sync.Once
	uid                string
}

// ListenerConfig specifies the networks configuration that ctrld will run on.
type ListenerConfig struct {
	IP              string                `mapstructure:"ip" toml:"ip,omitempty" validate:"iporempty"`
	Port            int                   `mapstructure:"port" toml:"port,omitempty" validate:"gte=0"`
	Restricted      bool                  `mapstructure:"restricted" toml:"restricted,omitempty"`
	AllowWanClients bool                  `mapstructure:"allow_wan_clients" toml:"allow_wan_clients,omitempty"`
	Policy          *ListenerPolicyConfig `mapstructure:"policy" toml:"policy,omitempty"`
}

// IsDirectDnsListener reports whether ctrld can be a direct listener on port 53.
// It returns true only if ctrld can listen on port 53 for all interfaces. That means
// there's no other software listening on port 53.
//
// If someone listening on port 53, or ctrld could only listen on port 53 for a specific
// interface, ctrld could only be configured as a DNS forwarder.
func (lc *ListenerConfig) IsDirectDnsListener() bool {
	if lc == nil || lc.Port != 53 {
		return false
	}
	switch lc.IP {
	case "", "::", "0.0.0.0":
		return true
	default:
		return false
	}
}

// ListenerPolicyConfig specifies the policy rules for ctrld to filter incoming requests.
type ListenerPolicyConfig struct {
	Name                 string   `mapstructure:"name" toml:"name,omitempty"`
	Networks             []Rule   `mapstructure:"networks" toml:"networks,omitempty,inline,multiline" validate:"dive,len=1"`
	Rules                []Rule   `mapstructure:"rules" toml:"rules,omitempty,inline,multiline" validate:"dive,len=1"`
	Macs                 []Rule   `mapstructure:"macs" toml:"macs,omitempty,inline,multiline" validate:"dive,len=1"`
	FailoverRcodes       []string `mapstructure:"failover_rcodes" toml:"failover_rcodes,omitempty" validate:"dive,dnsrcode"`
	FailoverRcodeNumbers []int    `mapstructure:"-" toml:"-"`
}

// Rule is a map from source to list of upstreams.
// ctrld uses rule to perform requests matching and forward
// the request to corresponding upstreams if it's matched.
type Rule map[string][]string

// Init initialized necessary values for an UpstreamConfig.
func (uc *UpstreamConfig) Init() {
	if err := uc.initDnsStamps(); err != nil {
		ProxyLogger.Load().Fatal().Err(err).Msg("invalid DNS Stamps")
	}
	uc.initDoHScheme()
	uc.uid = upstreamUID()
	if u, err := url.Parse(uc.Endpoint); err == nil {
		uc.Domain = u.Hostname()
		switch uc.Type {
		case ResolverTypeDOH, ResolverTypeDOH3:
			uc.u = u
		}
	}
	if uc.Domain == "" {
		if !strings.Contains(uc.Endpoint, ":") {
			uc.Domain = uc.Endpoint
			uc.Endpoint = net.JoinHostPort(uc.Endpoint, defaultPortFor(uc.Type))
		}
		host, _, _ := net.SplitHostPort(uc.Endpoint)
		uc.Domain = host
		if net.ParseIP(uc.Domain) != nil {
			uc.BootstrapIP = uc.Domain
		}
	}
	if uc.IPStack == "" {
		if uc.IsControlD() {
			uc.IPStack = IpStackSplit
		} else {
			uc.IPStack = IpStackBoth
		}
	}
}

// VerifyMsg creates and returns a new DNS message could be used for testing upstream health.
func (uc *UpstreamConfig) VerifyMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(".", dns.TypeNS)
	msg.SetEdns0(4096, false) // ensure handling of large DNS response
	return msg
}

// VerifyDomain returns the domain name that could be resolved by the upstream endpoint.
// It returns empty for non-ControlD upstream endpoint.
func (uc *UpstreamConfig) VerifyDomain() string {
	domain := uc.Domain
	if domain == "" {
		if u, err := url.Parse(uc.Endpoint); err == nil {
			domain = u.Hostname()
		}
	}
	for _, parent := range controldParentDomains {
		if dns.IsSubDomain(parent, domain) {
			return controldVerifiedDomain[parent]
		}
	}
	return ""
}

// UpstreamSendClientInfo reports whether the upstream is
// configured to send client info to the DNS server.
//
// Client info includes:
//   - MAC
//   - Lan IP
//   - Hostname
func (uc *UpstreamConfig) UpstreamSendClientInfo() bool {
	if uc.SendClientInfo != nil {
		return *uc.SendClientInfo
	}
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3:
		if uc.IsControlD() || uc.isNextDNS() {
			return true
		}
	}
	return false
}

// IsDiscoverable reports whether the upstream can be used for PTR discovery.
// The caller must ensure uc.Init() was called before calling this.
func (uc *UpstreamConfig) IsDiscoverable() bool {
	if uc.Discoverable != nil {
		return *uc.Discoverable
	}
	switch uc.Type {
	case ResolverTypeOS, ResolverTypeLegacy, ResolverTypePrivate, ResolverTypeLocal:
		if ip, err := netip.ParseAddr(uc.Domain); err == nil {
			return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || tsaddr.CGNATRange().Contains(ip)
		}
	}
	return false
}

// BootstrapIPs returns the bootstrap IPs list of upstreams.
func (uc *UpstreamConfig) BootstrapIPs() []string {
	return uc.bootstrapIPs
}

// SetCertPool sets the system cert pool used for TLS connections.
func (uc *UpstreamConfig) SetCertPool(cp *x509.CertPool) {
	uc.certPool = cp
}

// UID returns the unique identifier of the upstream.
func (uc *UpstreamConfig) UID() string {
	return uc.uid
}

// SetupBootstrapIP manually find all available IPs of the upstream.
// The first usable IP will be used as bootstrap IP of the upstream.
// The upstream domain will be looked up using following orders:
//
// - Current system DNS settings.
// - Direct IPs table for ControlD upstreams.
// - ControlD Bootstrap DNS 76.76.2.22
//
// The setup process will block until there's usable IPs found.
func (uc *UpstreamConfig) SetupBootstrapIP() {
	b := backoff.NewBackoff("setupBootstrapIP", func(format string, args ...any) {}, 10*time.Second)
	isControlD := uc.IsControlD()
	nss := initDefaultOsResolver()
	for {
		uc.bootstrapIPs = lookupIP(uc.Domain, uc.Timeout, nss)
		// For ControlD upstream, the bootstrap IPs could not be RFC 1918 addresses,
		// filtering them out here to prevent weird behavior.
		if isControlD {
			n := 0
			for _, ip := range uc.bootstrapIPs {
				netIP := net.ParseIP(ip)
				if netIP != nil && !netIP.IsPrivate() {
					uc.bootstrapIPs[n] = ip
					n++
				}
			}
			uc.bootstrapIPs = uc.bootstrapIPs[:n]
			if len(uc.bootstrapIPs) == 0 {
				uc.bootstrapIPs = bootstrapIPsFromControlDDomain(uc.Domain)
				ProxyLogger.Load().Warn().Msgf("no record found for %q, lookup from direct IP table", uc.Domain)
			}
		}
		if len(uc.bootstrapIPs) == 0 {
			ProxyLogger.Load().Warn().Msgf("no record found for %q, using bootstrap server: %s", uc.Domain, PremiumDNSBoostrapIP)
			uc.bootstrapIPs = lookupIP(uc.Domain, uc.Timeout, []string{net.JoinHostPort(PremiumDNSBoostrapIP, "53")})

		}
		if len(uc.bootstrapIPs) > 0 {
			break
		}
		ProxyLogger.Load().Warn().Msg("could not resolve bootstrap IPs, retrying...")
		b.BackOff(context.Background(), errors.New("no bootstrap IPs"))
	}
	for _, ip := range uc.bootstrapIPs {
		if ctrldnet.IsIPv6(ip) {
			uc.bootstrapIPs6 = append(uc.bootstrapIPs6, ip)
		} else {
			uc.bootstrapIPs4 = append(uc.bootstrapIPs4, ip)
		}
	}
	ProxyLogger.Load().Debug().Msgf("bootstrap IPs: %v", uc.bootstrapIPs)
}

// ReBootstrap re-setup the bootstrap IP and the transport.
func (uc *UpstreamConfig) ReBootstrap() {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3:
	default:
		return
	}
	_, _, _ = uc.g.Do("ReBootstrap", func() (any, error) {
		if uc.rebootstrap.CompareAndSwap(false, true) {
			ProxyLogger.Load().Debug().Msgf("re-bootstrapping upstream ip for %v", uc)
		}
		return true, nil
	})
}

// SetupTransport initializes the network transport used to connect to upstream server.
// For now, only DoH upstream is supported.
func (uc *UpstreamConfig) SetupTransport() {
	switch uc.Type {
	case ResolverTypeDOH:
		uc.setupDOHTransport()
	case ResolverTypeDOH3:
		uc.setupDOH3Transport()
	}
}

func (uc *UpstreamConfig) setupDOHTransport() {
	switch uc.IPStack {
	case IpStackBoth, "":
		uc.transport = uc.newDOHTransport(uc.bootstrapIPs)
	case IpStackV4:
		uc.transport = uc.newDOHTransport(uc.bootstrapIPs4)
	case IpStackV6:
		uc.transport = uc.newDOHTransport(uc.bootstrapIPs6)
	case IpStackSplit:
		uc.transport4 = uc.newDOHTransport(uc.bootstrapIPs4)
		if HasIPv6() {
			uc.transport6 = uc.newDOHTransport(uc.bootstrapIPs6)
		} else {
			uc.transport6 = uc.transport4
		}
		uc.transport = uc.newDOHTransport(uc.bootstrapIPs)
	}
}

func (uc *UpstreamConfig) newDOHTransport(addrs []string) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 100
	transport.TLSClientConfig = &tls.Config{
		RootCAs:            uc.certPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	// Prevent bad tcp connection hanging the requests for too long.
	// See: https://github.com/golang/go/issues/36026
	if t2, err := http2.ConfigureTransports(transport); err == nil {
		t2.ReadIdleTimeout = 10 * time.Second
		t2.PingTimeout = 5 * time.Second
	}

	dialerTimeoutMs := 2000
	if uc.Timeout > 0 && uc.Timeout < dialerTimeoutMs {
		dialerTimeoutMs = uc.Timeout
	}
	dialerTimeout := time.Duration(dialerTimeoutMs) * time.Millisecond
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if uc.BootstrapIP != "" {
			dialer := net.Dialer{Timeout: dialerTimeout, KeepAlive: dialerTimeout}
			addr := net.JoinHostPort(uc.BootstrapIP, port)
			Log(ctx, ProxyLogger.Load().Debug(), "sending doh request to: %s", addr)
			return dialer.DialContext(ctx, network, addr)
		}
		pd := &ctrldnet.ParallelDialer{}
		pd.Timeout = dialerTimeout
		pd.KeepAlive = dialerTimeout
		dialAddrs := make([]string, len(addrs))
		for i := range addrs {
			dialAddrs[i] = net.JoinHostPort(addrs[i], port)
		}
		conn, err := pd.DialContext(ctx, network, dialAddrs, ProxyLogger.Load())
		if err != nil {
			return nil, err
		}
		Log(ctx, ProxyLogger.Load().Debug(), "sending doh request to: %s", conn.RemoteAddr())
		return conn, nil
	}
	runtime.SetFinalizer(transport, func(transport *http.Transport) {
		transport.CloseIdleConnections()
	})
	return transport
}

// Ping warms up the connection to DoH/DoH3 upstream.
func (uc *UpstreamConfig) Ping() {
	if err := uc.ping(); err != nil {
		ProxyLogger.Load().Debug().Err(err).Msgf("upstream ping failed: %s", uc.Endpoint)
		_ = uc.FallbackToDirectIP()
	}
}

// ErrorPing is like Ping, but return an error if any.
func (uc *UpstreamConfig) ErrorPing() error {
	return uc.ping()
}

func (uc *UpstreamConfig) ping() error {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3:
	default:
		return nil
	}

	ping := func(t http.RoundTripper) error {
		if t == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "HEAD", uc.Endpoint, nil)
		if err != nil {
			return err
		}
		resp, err := t.RoundTrip(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		switch uc.Type {
		case ResolverTypeDOH:
			if err := ping(uc.dohTransport(typ)); err != nil {
				return err
			}
		case ResolverTypeDOH3:
			if err := ping(uc.doh3Transport(typ)); err != nil {
				return err
			}
		}
	}

	return nil
}

// IsControlD reports whether this is a ControlD upstream.
func (uc *UpstreamConfig) IsControlD() bool {
	domain := uc.Domain
	if domain == "" {
		if u, err := url.Parse(uc.Endpoint); err == nil {
			domain = u.Hostname()
		}
	}
	for _, parent := range controldParentDomains {
		if dns.IsSubDomain(parent, domain) {
			return true
		}
	}
	return false
}

func (uc *UpstreamConfig) isNextDNS() bool {
	domain := uc.Domain
	if domain == "" {
		if u, err := url.Parse(uc.Endpoint); err == nil {
			domain = u.Hostname()
		}
	}
	return domain == "dns.nextdns.io"
}

func (uc *UpstreamConfig) dohTransport(dnsType uint16) http.RoundTripper {
	uc.transportOnce.Do(func() {
		uc.SetupTransport()
	})
	if uc.rebootstrap.CompareAndSwap(true, false) {
		uc.SetupTransport()
	}
	switch uc.IPStack {
	case IpStackBoth, IpStackV4, IpStackV6:
		return uc.transport
	case IpStackSplit:
		switch dnsType {
		case dns.TypeA:
			return uc.transport4
		default:
			return uc.transport6
		}
	}
	return uc.transport
}

func (uc *UpstreamConfig) bootstrapIPForDNSType(dnsType uint16) string {
	switch uc.IPStack {
	case IpStackBoth:
		return pick(uc.bootstrapIPs)
	case IpStackV4:
		return pick(uc.bootstrapIPs4)
	case IpStackV6:
		return pick(uc.bootstrapIPs6)
	case IpStackSplit:
		switch dnsType {
		case dns.TypeA:
			return pick(uc.bootstrapIPs4)
		default:
			if HasIPv6() {
				return pick(uc.bootstrapIPs6)
			}
			return pick(uc.bootstrapIPs4)
		}
	}
	return pick(uc.bootstrapIPs)
}

func (uc *UpstreamConfig) netForDNSType(dnsType uint16) (string, string) {
	switch uc.IPStack {
	case IpStackBoth:
		return "tcp-tls", "udp"
	case IpStackV4:
		return "tcp4-tls", "udp4"
	case IpStackV6:
		return "tcp6-tls", "udp6"
	case IpStackSplit:
		switch dnsType {
		case dns.TypeA:
			return "tcp4-tls", "udp4"
		default:
			if HasIPv6() {
				return "tcp6-tls", "udp6"
			}
			return "tcp4-tls", "udp4"
		}
	}
	return "tcp-tls", "udp"
}

// initDoHScheme initializes the endpoint scheme for DoH/DoH3 upstream if not present.
func (uc *UpstreamConfig) initDoHScheme() {
	if strings.HasPrefix(uc.Endpoint, endpointPrefixH3) && uc.Type == "" {
		uc.Type = ResolverTypeDOH3
	}
	switch uc.Type {
	case ResolverTypeDOH:
	case ResolverTypeDOH3:
		if after, found := strings.CutPrefix(uc.Endpoint, endpointPrefixH3); found {
			uc.Endpoint = endpointPrefixHTTPS + after
		}
	default:
		return
	}
	if !strings.HasPrefix(uc.Endpoint, endpointPrefixHTTPS) {
		uc.Endpoint = endpointPrefixHTTPS + uc.Endpoint
	}
}

// initDnsStamps initializes upstream config based on encoded DNS Stamps Endpoint.
func (uc *UpstreamConfig) initDnsStamps() error {
	if strings.HasPrefix(uc.Endpoint, endpointPrefixSdns) && uc.Type == "" {
		uc.Type = ResolverTypeSDNS
	}
	if uc.Type != ResolverTypeSDNS {
		return nil
	}
	sdns, err := dnsstamps.NewServerStampFromString(uc.Endpoint)
	if err != nil {
		return err
	}
	ip, port, _ := net.SplitHostPort(sdns.ServerAddrStr)
	providerName, port2, _ := net.SplitHostPort(sdns.ProviderName)
	if port2 != "" {
		port = port2
	}
	if providerName == "" {
		providerName = sdns.ProviderName
	}
	switch sdns.Proto {
	case dnsstamps.StampProtoTypeDoH:
		uc.Type = ResolverTypeDOH
		host := sdns.ProviderName
		if port != "" && port != defaultPortFor(uc.Type) {
			host = net.JoinHostPort(providerName, port)
		}
		uc.Endpoint = "https://" + host + sdns.Path
	case dnsstamps.StampProtoTypeTLS:
		uc.Type = ResolverTypeDOT
		uc.Endpoint = net.JoinHostPort(providerName, port)
	case dnsstamps.StampProtoTypeDoQ:
		uc.Type = ResolverTypeDOQ
		uc.Endpoint = net.JoinHostPort(providerName, port)
	case dnsstamps.StampProtoTypePlain:
		uc.Type = ResolverTypeLegacy
		uc.Endpoint = sdns.ServerAddrStr
	default:
		return fmt.Errorf("unsupported stamp protocol %q", sdns.Proto)
	}
	uc.BootstrapIP = ip
	return nil
}

// Context returns a new context with timeout set from upstream config.
func (uc *UpstreamConfig) Context(ctx context.Context) (context.Context, context.CancelFunc) {
	if uc.Timeout > 0 {
		return context.WithTimeout(ctx, time.Millisecond*time.Duration(uc.Timeout))
	}
	return context.WithCancel(ctx)
}

// FallbackToDirectIP changes ControlD upstream endpoint to use direct IP instead of domain.
func (uc *UpstreamConfig) FallbackToDirectIP() bool {
	if !uc.IsControlD() {
		return false
	}
	if uc.u == nil || uc.Domain == "" {
		return false
	}

	done := false
	uc.fallbackOnce.Do(func() {
		var ip string
		switch {
		case dns.IsSubDomain(PremiumDnsDomain, uc.Domain):
			ip = PremiumDNSBoostrapIP
		case dns.IsSubDomain(FreeDnsDomain, uc.Domain):
			ip = FreeDNSBoostrapIP
		default:
			return
		}
		ProxyLogger.Load().Warn().Msgf("using direct IP for %q: %s", uc.Endpoint, ip)
		uc.u.Host = ip
		done = true
	})
	return done
}

// Init initialized necessary values for an ListenerConfig.
func (lc *ListenerConfig) Init() {
	if lc.Policy != nil {
		lc.Policy.FailoverRcodeNumbers = make([]int, len(lc.Policy.FailoverRcodes))
		for i, rcode := range lc.Policy.FailoverRcodes {
			lc.Policy.FailoverRcodeNumbers[i] = dnsrcode.FromString(rcode)
		}
	}
}

// ValidateConfig validates the given config.
func ValidateConfig(validate *validator.Validate, cfg *Config) error {
	_ = validate.RegisterValidation("dnsrcode", validateDnsRcode)
	_ = validate.RegisterValidation("ipstack", validateIpStack)
	_ = validate.RegisterValidation("iporempty", validateIpOrEmpty)
	validate.RegisterStructValidation(upstreamConfigStructLevelValidation, UpstreamConfig{})
	return validate.Struct(cfg)
}

func validateDnsRcode(fl validator.FieldLevel) bool {
	return dnsrcode.FromString(fl.Field().String()) != -1
}

func validateIpStack(fl validator.FieldLevel) bool {
	switch fl.Field().String() {
	case IpStackBoth, IpStackV4, IpStackV6, IpStackSplit, "":
		return true
	default:
		return false
	}
}

func validateIpOrEmpty(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	return net.ParseIP(val) != nil
}

func upstreamConfigStructLevelValidation(sl validator.StructLevel) {
	uc := sl.Current().Addr().Interface().(*UpstreamConfig)
	if uc.Type == ResolverTypeOS {
		return
	}

	// Endpoint is required for non os resolver.
	if uc.Endpoint == "" {
		sl.ReportError(uc.Endpoint, "endpoint", "Endpoint", "required_unless", "")
		return
	}

	// Empty type is ok only for endpoints starts with "h3://" and "sdns://".
	if uc.Type == "" && !strings.HasPrefix(uc.Endpoint, endpointPrefixH3) && !strings.HasPrefix(uc.Endpoint, endpointPrefixSdns) {
		sl.ReportError(uc.Endpoint, "type", "type", "oneof", "doh doh3 dot doq os legacy sdns")
		return
	}

	// initDoHScheme/initDnsStamps may change upstreams information,
	// so restoring changed values after validation to keep original one.
	defer func(ep, typ string) {
		uc.Endpoint = ep
		uc.Type = typ
	}(uc.Endpoint, uc.Type)

	if err := uc.initDnsStamps(); err != nil {
		sl.ReportError(uc.Endpoint, "endpoint", "Endpoint", "http_url", "")
		return
	}
	uc.initDoHScheme()
	// DoH/DoH3 requires endpoint is an HTTP url.
	if uc.Type == ResolverTypeDOH || uc.Type == ResolverTypeDOH3 {
		u, err := url.Parse(uc.Endpoint)
		if err != nil || u.Host == "" {
			sl.ReportError(uc.Endpoint, "endpoint", "Endpoint", "http_url", "")
			return
		}
	}
}

func defaultPortFor(typ string) string {
	switch typ {
	case ResolverTypeDOH, ResolverTypeDOH3:
		return "443"
	case ResolverTypeDOQ, ResolverTypeDOT:
		return "853"
	case ResolverTypeLegacy:
		return "53"
	}
	return "53"
}

// ResolverTypeFromEndpoint tries guessing the resolver type with a given endpoint
// using following rules:
//
// - If endpoint is an IP address ->  ResolverTypeLegacy
// - If endpoint starts with "https://" -> ResolverTypeDOH
// - If endpoint starts with "quic://" -> ResolverTypeDOQ
// - If endpoint starts with "h3://" -> ResolverTypeDOH3
// - If endpoint starts with "sdns://" -> ResolverTypeSDNS
// - For anything else -> ResolverTypeDOT
func ResolverTypeFromEndpoint(endpoint string) string {
	switch {
	case strings.HasPrefix(endpoint, endpointPrefixHTTPS):
		return ResolverTypeDOH
	case strings.HasPrefix(endpoint, endpointPrefixQUIC):
		return ResolverTypeDOQ
	case strings.HasPrefix(endpoint, endpointPrefixH3):
		return ResolverTypeDOH3
	case strings.HasPrefix(endpoint, endpointPrefixSdns):
		return ResolverTypeSDNS
	}
	host := endpoint
	if strings.Contains(endpoint, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ResolverTypeLegacy
	}
	return ResolverTypeDOT
}

func pick(s []string) string {
	return s[rand.Intn(len(s))]
}

// upstreamUID generates an unique identifier for an upstream.
func upstreamUID() string {
	b := make([]byte, 4)
	for {
		if _, err := crand.Read(b); err != nil {
			ProxyLogger.Load().Warn().Err(err).Msg("could not generate uid for upstream, retrying...")
			continue
		}
		return hex.EncodeToString(b)
	}
}

// String returns a string representation of the UpstreamConfig for logging.
func (uc *UpstreamConfig) String() string {
	if uc == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{name: %q, type: %q, endpoint: %q, bootstrap_ip: %q, domain: %q, ip_stack: %q}",
		uc.Name, uc.Type, uc.Endpoint, uc.BootstrapIP, uc.Domain, uc.IPStack)
}

// bootstrapIPsFromControlDDomain returns bootstrap IPs for ControlD domain.
func bootstrapIPsFromControlDDomain(domain string) []string {
	switch {
	case dns.IsSubDomain(PremiumDnsDomain, domain):
		return []string{PremiumDNSBoostrapIP, PremiumDNSBoostrapIPv6}
	case dns.IsSubDomain(FreeDnsDomain, domain):
		return []string{FreeDNSBoostrapIP, FreeDNSBoostrapIPv6}
	case dns.IsSubDomain(premiumDnsDomainDev, domain):
		return []string{premiumDNSBoostrapIP, premiumDNSBoostrapIPv6}
	case dns.IsSubDomain(freeDnsDomainDev, domain):
		return []string{freeDNSBoostrapIP, freeDNSBoostrapIPv6}
	}
	return nil
}

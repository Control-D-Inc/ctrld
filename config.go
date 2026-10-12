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

	// nextDNSDomain is the parent domain of the NextDNS DoH endpoints. Beside
	// dns.nextdns.io, NextDNS serves alternative endpoints under it, such as
	// ultralow.dns.nextdns.io and anycast.dns2.nextdns.io, which are the same
	// service and take the same client info headers.
	nextDNSDomain = "nextdns.io"

	endpointPrefixHTTPS = "https://"
	endpointPrefixQUIC  = "quic://"
	endpointPrefixH3    = "h3://"
	endpointPrefixSdns  = "sdns://"

	rebootstrapNotStarted = 0
	rebootstrapStarted    = 1
	rebootstrapInProgress = 2
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
	ctx := context.Background()
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "Config initialization started")

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

	Log(ctx, logger.Debug(), "Config initialization completed")
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
	// AllowUnprivilegedLogSend is a macOS-only, administrator-controlled opt-in.
	AllowUnprivilegedLogSend bool `mapstructure:"allow_unprivileged_log_send" toml:"allow_unprivileged_log_send,omitempty"`

	LogLevel                string         `mapstructure:"log_level" toml:"log_level,omitempty"`
	LogPath                 string         `mapstructure:"log_path" toml:"log_path,omitempty"`
	LogMaxSizeMB            int            `mapstructure:"log_max_size_mb" toml:"log_max_size_mb,omitempty" validate:"omitempty,gte=1,lte=1024"`
	LogMaxBackups           *int           `mapstructure:"log_max_backups" toml:"log_max_backups,omitempty" validate:"omitempty,gte=0,lte=64"`
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
	InterceptMode           string         `mapstructure:"intercept_mode" toml:"intercept_mode,omitempty" validate:"omitempty,oneof=off dns hard"`
	NRPTRecoveryMaxAttempts *int           `mapstructure:"nrpt_recovery_max_attempts" toml:"nrpt_recovery_max_attempts,omitempty" validate:"omitempty,gte=0"`
	NRPTRecoveryCooldown    *time.Duration `mapstructure:"nrpt_recovery_cooldown" toml:"nrpt_recovery_cooldown,omitempty"`
	// FirewallMode controls the DNS-resolved IP allowlist. When "on", only IPs
	// that were successfully resolved by ctrld are allowed for outbound connections.
	// This closes the "DNS gap" where apps bypass DNS policy using hardcoded IPs.
	// Requires intercept mode to be active for enforcement on desktop platforms.
	// On mobile, the netstack layer uses the allowlist directly.
	FirewallMode string `mapstructure:"firewall_mode" toml:"firewall_mode,omitempty" validate:"omitempty,oneof=off on"`
	// FirewallForwardedSources lists VM/container source subnets (CIDR) whose
	// forwarded/NATed DNS is redirected through ctrld under Firewall Mode, so
	// guest resolutions are policy-enforced and populate the allowlist, and guest
	// egress to allowed destinations is permitted without an interface-wide
	// bypass. These augment auto-detection of VM networks and are the supported way
	// to trust a stack that auto-detection cannot prove ownership of. Empty (the
	// default) preserves prior behavior. macOS only; see
	// buildPFForwardedSourceRules.
	//
	// Deliberately not validated with `cidr`: entries are checked at use time and a
	// bad one is dropped with a warning while the rest of the set still applies
	// (see firewallForwardedSources). A hard validator here would make one typo in
	// an MDM-pushed subnet fatal at startup - validateConfig exits the process -
	// taking down DNS service for the whole host over a line that only ever
	// widened a firewall allowance.
	FirewallForwardedSources []string `mapstructure:"firewall_forwarded_sources" toml:"firewall_forwarded_sources,omitempty"`
	Daemon                   bool     `mapstructure:"-" toml:"-"`
	AllocateIP               bool     `mapstructure:"-" toml:"-"`
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
	// InternalDomain is set only by ctrld, on the upstreams it generates for
	// organization Internal Domains, to the mode they serve. It is never read
	// from or written to a configuration file, so an upstream a configuration
	// defines is never mistaken for a generated one, whatever it is named.
	InternalDomain string `mapstructure:"-" toml:"-"`
	IPStack        string `mapstructure:"ip_stack" toml:"ip_stack,omitempty" validate:"ipstack"`
	Timeout        int    `mapstructure:"timeout" toml:"timeout,omitempty" validate:"gte=0"`
	// The caller should not access this field directly.
	// Use UpstreamSendClientInfo instead.
	SendClientInfo *bool `mapstructure:"send_client_info" toml:"send_client_info,omitempty"`
	// The caller should not access this field directly.
	// Use IsDiscoverable instead.
	Discoverable *bool `mapstructure:"discoverable" toml:"discoverable"`

	g                  singleflight.Group
	rebootstrap        atomic.Int64
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
	doqConnPool        *doqConnPool
	doqConnPool4       *doqConnPool
	doqConnPool6       *doqConnPool
	dotClientPool      *dotConnPool
	dotClientPool4     *dotConnPool
	dotClientPool6     *dotConnPool
	certPool           *x509.CertPool
	u                  *url.URL
	fallbackOnce       sync.Once
	uid                string

	// bootstrapIncomplete is set while the bootstrap addresses lack a family
	// the ip_stack needs; the next re-bootstrap looks them up again.
	bootstrapIncomplete atomic.Bool
	// directFallback is set once FallbackToDirectIP has fired: DoH and DoH3
	// then also try the Control D direct IPs when the bootstrap addresses fail.
	directFallback atomic.Bool
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

// MatchingConfig defines the configuration for rule matching behavior
type MatchingConfig struct {
	Order []string `mapstructure:"order" toml:"order,omitempty"`
}

// ListenerPolicyConfig specifies the policy rules for ctrld to filter incoming requests.
type ListenerPolicyConfig struct {
	Name                 string          `mapstructure:"name" toml:"name,omitempty"`
	Networks             []Rule          `mapstructure:"networks" toml:"networks,omitempty,inline,multiline" validate:"dive,len=1"`
	Rules                []Rule          `mapstructure:"rules" toml:"rules,omitempty,inline,multiline" validate:"dive,len=1"`
	Macs                 []Rule          `mapstructure:"macs" toml:"macs,omitempty,inline,multiline" validate:"dive,len=1"`
	FailoverRcodes       []string        `mapstructure:"failover_rcodes" toml:"failover_rcodes,omitempty" validate:"dive,dnsrcode"`
	FailoverRcodeNumbers []int           `mapstructure:"-" toml:"-"`
	Matching             *MatchingConfig `mapstructure:"-" toml:"-"`
}

// Rule is a map from source to list of upstreams.
// ctrld uses rule to perform requests matching and forward
// the request to corresponding upstreams if it's matched.
type Rule map[string][]string

// Init initialized necessary values for an UpstreamConfig.
func (uc *UpstreamConfig) Init(ctx context.Context) {
	logger := LoggerFromCtx(ctx)
	if err := uc.initDnsStamps(); err != nil {
		logger.Fatal().Err(err).Msg("Invalid dns stamps")
	}
	uc.initDoHScheme()
	uc.uid = upstreamUID(ctx)
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
		// Set default IP stack based on upstream type
		// Control-D upstreams use split stack for better IPv4/IPv6 handling,
		// while other upstreams use both stacks for maximum compatibility
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
// configured to send client info to Control D DNS server.
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
	case ResolverTypeOS, ResolverTypeLegacy, ResolverTypePrivate:
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

// bootstrapLookupFn resolves domain for bootstrapping. It is a variable so
// tests control the lookup result.
var bootstrapLookupFn = lookupIP

// SetupBootstrapIP sets up bootstrap IPs for the upstream config.
// The upstream domain will be looked up using following orders:
//
// - Current system DNS settings.
// - Direct IPs table for ControlD upstreams.
// - ControlD Bootstrap DNS 76.76.2.22
//
// The later sources fill in what the earlier ones could not: the whole list,
// and also an address family the ip_stack needs that a lookup left out, such
// as an AAAA-only answer for a split-stack upstream, whose A queries need IPv4.
//
// The setup process will block until there's usable IPs found. A result that
// still lacks a needed family is used as it is, and the next re-bootstrap
// looks the missing family up again.
func (uc *UpstreamConfig) SetupBootstrapIP(ctx context.Context) {
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "Setting up bootstrap IPs for upstream: %s", uc.Name)

	b := backoff.NewBackoff("setupBootstrapIP", func(format string, args ...any) {}, 10*time.Second)
	nss := initDefaultOsResolver(ctx)
	for {
		if ips := uc.lookupBootstrapIPs(ctx, nss); len(ips) > 0 {
			uc.setBootstrapIPs(ctx, ips)
			break
		}
		logger.Warn().Msg("Could not resolve bootstrap ips, retrying...")
		b.BackOff(context.Background(), errors.New("no bootstrap IPs"))
	}
	logger.Debug().Msgf("Bootstrap ips: %v", uc.bootstrapIPs)
	Log(ctx, logger.Debug(), "Bootstrap IP setup completed for upstream: %s", uc.Name)
}

// lookupBootstrapIPs runs one round of the bootstrap lookup through nss and the
// fallback sources, and returns what it found, which may be incomplete for the
// ip_stack or empty.
func (uc *UpstreamConfig) lookupBootstrapIPs(ctx context.Context, nss []string) []string {
	logger := LoggerFromCtx(ctx)
	isControlD := uc.IsControlD()
	Log(ctx, logger.Debug(), "Looking up bootstrap IPs for domain: %s", uc.Domain)
	ips := bootstrapLookupFn(ctx, uc.Domain, uc.Timeout, nss)
	// For ControlD upstream, the bootstrap IPs could not be RFC 1918 addresses,
	// filtering them out here to prevent weird behavior.
	if isControlD {
		n := 0
		for _, ip := range ips {
			netIP := net.ParseIP(ip)
			if netIP != nil && !netIP.IsPrivate() {
				ips[n] = ip
				n++
			}
		}
		ips = ips[:n]
		if !uc.bootstrapComplete(ctx, ips) {
			logger.Warn().Msgf("Incomplete records for %q (%v), filling in from direct ip table", uc.Domain, ips)
			ips = mergeMissingFamilies(ips, bootstrapIPsFromControlDDomain(uc.Domain))
		}
	}
	if !uc.bootstrapComplete(ctx, ips) {
		logger.Warn().Msgf("Incomplete records for %q (%v), using bootstrap server: %s", uc.Domain, ips, PremiumDNSBoostrapIP)
		ips = mergeMissingFamilies(ips, bootstrapLookupFn(ctx, uc.Domain, uc.Timeout, []string{net.JoinHostPort(PremiumDNSBoostrapIP, "53")}))
	}
	return ips
}

// setBootstrapIPs replaces the bootstrap addresses, and records whether they
// cover the families the ip_stack needs.
func (uc *UpstreamConfig) setBootstrapIPs(ctx context.Context, ips []string) {
	ips4, ips6 := splitAddressFamilies(ips)
	uc.bootstrapIPs, uc.bootstrapIPs4, uc.bootstrapIPs6 = ips, ips4, ips6
	complete := uc.bootstrapComplete(ctx, ips)
	uc.bootstrapIncomplete.Store(!complete)
	if !complete {
		logger := LoggerFromCtx(ctx)
		logger.Warn().Msgf("Bootstrap ips for %q lack an address family needed by ip_stack %q: %v; will look up again on re-bootstrap", uc.Domain, uc.IPStack, ips)
	}
}

// bootstrapComplete reports whether ips cover the address families the
// upstream's ip_stack needs: IPv4 for v4, IPv6 for v6, either for both, and
// for split IPv4 for A queries plus IPv6 for the others when the host has IPv6.
// An IPv4-only host never needs IPv6.
func (uc *UpstreamConfig) bootstrapComplete(ctx context.Context, ips []string) bool {
	ips4, ips6 := splitAddressFamilies(ips)
	switch uc.IPStack {
	case IpStackV4:
		return len(ips4) > 0
	case IpStackV6:
		return len(ips6) > 0
	case IpStackSplit:
		return len(ips4) > 0 && (len(ips6) > 0 || !HasIPv6(ctx))
	}
	return len(ips) > 0
}

// splitAddressFamilies returns the IPv4 and the IPv6 addresses of ips.
func splitAddressFamilies(ips []string) (ips4, ips6 []string) {
	for _, ip := range ips {
		if ctrldnet.IsIPv6(ip) {
			ips6 = append(ips6, ip)
		} else {
			ips4 = append(ips4, ip)
		}
	}
	return ips4, ips6
}

// mergeMissingFamilies adds to ips the addresses of extra whose family ips
// does not have at all. A family ips already has is kept as it is.
func mergeMissingFamilies(ips, extra []string) []string {
	ips4, ips6 := splitAddressFamilies(ips)
	extra4, extra6 := splitAddressFamilies(extra)
	merged := append([]string{}, ips...)
	if len(ips4) == 0 {
		merged = append(merged, extra4...)
	}
	if len(ips6) == 0 {
		merged = append(merged, extra6...)
	}
	return merged
}

// refreshIncompleteBootstrap looks the bootstrap addresses up again, once, when
// they lack a family the ip_stack needs. Rebuilding the transports from the
// same incomplete lists would never recover; this picks up the missing family
// once DNS is reachable again. Families it still cannot find keep their current
// addresses.
func (uc *UpstreamConfig) refreshIncompleteBootstrap(ctx context.Context) {
	if uc.BootstrapIP != "" || !uc.bootstrapIncomplete.Load() {
		return
	}
	ips := uc.lookupBootstrapIPs(ctx, initDefaultOsResolver(ctx))
	if !uc.bootstrapComplete(ctx, ips) {
		ips = mergeMissingFamilies(ips, uc.bootstrapIPs)
	}
	if len(ips) == 0 {
		return
	}
	uc.setBootstrapIPs(ctx, ips)
	logger := LoggerFromCtx(ctx)
	logger.Debug().Msgf("Refreshed bootstrap ips for %q: %v", uc.Domain, ips)
}

// ReBootstrap re-setup the bootstrap IP and the transport.
func (uc *UpstreamConfig) ReBootstrap(ctx context.Context) {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3, ResolverTypeDOQ, ResolverTypeDOT:
	default:
		return
	}
	_, _, _ = uc.g.Do("ReBootstrap", func() (any, error) {
		if uc.rebootstrap.CompareAndSwap(rebootstrapNotStarted, rebootstrapStarted) {
			logger := LoggerFromCtx(ctx)
			Log(ctx, logger.Debug(), "Re-bootstrapping upstream: %s", uc.Name)
		}
		return true, nil
	})
}

// ForceReBootstrap immediately creates a new transport (closing old idle
// connections first) without waiting for the lazy re-bootstrap mechanism.
// Used after pf state table flushes where existing TCP/QUIC connections
// are dead and we need fresh connections immediately.
func (uc *UpstreamConfig) ForceReBootstrap(ctx context.Context) {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3, ResolverTypeDOQ, ResolverTypeDOT:
	default:
		return
	}
	logger := LoggerFromCtx(ctx)
	Log(ctx, logger.Debug(), "force re-bootstrapping upstream transport for %v", uc)
	uc.closeTransports()
	uc.refreshIncompleteBootstrap(ctx)
	uc.SetupTransport(ctx)
	// Clear any pending lazy re-bootstrap flag so ensureSetupTransport()
	// doesn't redundantly recreate the transport we just built.
	uc.rebootstrap.Store(rebootstrapNotStarted)
}

// CloseTransports retires the upstream's transports, including active DoT and
// HTTP/3 connections. Callers must stop publishing this upstream before calling
// it and must not reuse it without calling SetupTransport.
func (uc *UpstreamConfig) CloseTransports() {
	uc.retireTransports()
}

// retireTransports permanently closes DoT pools and HTTP/3 transports before
// their owner discards them. Like closeTransports, it does not acquire an
// upstream lock: callers that serialize slot access must keep that serialization
// across retirement and replacement.
func (uc *UpstreamConfig) retireTransports() {
	uc.closeTransports()
	for _, p := range []*dotConnPool{uc.dotClientPool, uc.dotClientPool4, uc.dotClientPool6} {
		if p != nil {
			p.Close()
		}
	}
	// Unlike CloseIdleConnections, Close also cancels pending dials and active
	// HTTP/3 requests, and prevents late requests from reviving the transport.
	for _, rt := range []http.RoundTripper{uc.http3RoundTripper, uc.http3RoundTripper4, uc.http3RoundTripper6} {
		if c, ok := rt.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
}

// closeTransports closes idle connections on all existing transports.
// It does not retire DoT pools or HTTP/3 transports: active work may continue
// and the resources remain usable. Use retireTransports before replacing them.
func (uc *UpstreamConfig) closeTransports() {
	for _, t := range []*http.Transport{uc.transport, uc.transport4, uc.transport6} {
		if t != nil {
			t.CloseIdleConnections()
		}
	}
	for _, p := range []*doqConnPool{uc.doqConnPool, uc.doqConnPool4, uc.doqConnPool6} {
		if p != nil {
			p.CloseIdleConnections()
		}
	}
	for _, p := range []*dotConnPool{uc.dotClientPool, uc.dotClientPool4, uc.dotClientPool6} {
		if p != nil {
			p.CloseIdleConnections()
		}
	}
	for _, rt := range []http.RoundTripper{uc.http3RoundTripper, uc.http3RoundTripper4, uc.http3RoundTripper6} {
		if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// SetupTransport initializes the network transport used to connect to upstream servers.
// For now, DoH/DoH3/DoQ/DoT upstreams are supported.
func (uc *UpstreamConfig) SetupTransport(ctx context.Context) {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3, ResolverTypeDOQ, ResolverTypeDOT:
	default:
		return
	}

	// Retire old DoT/HTTP3 resources before replacing their slots. Idle-only
	// cleanup would leave active queries and late work owning orphaned resources.
	// DoH and DoQ retain their existing cleanup semantics.
	uc.retireTransports()

	ips := uc.bootstrapIPs
	switch uc.IPStack {
	case IpStackV4:
		ips = uc.bootstrapIPs4
	case IpStackV6:
		ips = uc.bootstrapIPs6
	}
	uc.transport = uc.newDOHTransport(ctx, ips)
	uc.http3RoundTripper = uc.newDOH3Transport(ctx, ips)
	uc.doqConnPool = uc.newDOQConnPool(ctx, ips)
	uc.dotClientPool = uc.newDOTClientPool(ctx, ips)
	if uc.IPStack == IpStackSplit {
		// Split picks the transport by query type, not a hard family limit:
		// while a family is missing, its queries borrow the other family's
		// addresses rather than fail on an empty transport until the
		// re-bootstrap finds it (refreshIncompleteBootstrap).
		ips4, ips6 := uc.bootstrapIPs4, uc.bootstrapIPs6
		if len(ips4) == 0 {
			ips4 = ips6
		}
		if len(ips6) == 0 {
			ips6 = ips4
		}
		uc.transport4 = uc.newDOHTransport(ctx, ips4)
		uc.http3RoundTripper4 = uc.newDOH3Transport(ctx, ips4)
		uc.doqConnPool4 = uc.newDOQConnPool(ctx, ips4)
		uc.dotClientPool4 = uc.newDOTClientPool(ctx, ips4)
		if HasIPv6(ctx) {
			uc.transport6 = uc.newDOHTransport(ctx, ips6)
			uc.http3RoundTripper6 = uc.newDOH3Transport(ctx, ips6)
			uc.doqConnPool6 = uc.newDOQConnPool(ctx, ips6)
			uc.dotClientPool6 = uc.newDOTClientPool(ctx, ips6)
		} else {
			uc.transport6 = uc.transport4
			uc.http3RoundTripper6 = uc.http3RoundTripper4
			uc.doqConnPool6 = uc.doqConnPool4
			uc.dotClientPool6 = uc.dotClientPool4
		}
	}
}

func (uc *UpstreamConfig) ensureSetupTransport(ctx context.Context) {
	uc.transportOnce.Do(func() {
		uc.SetupTransport(ctx)
	})

	if uc.rebootstrap.CompareAndSwap(rebootstrapStarted, rebootstrapInProgress) {
		uc.refreshIncompleteBootstrap(ctx)
		uc.SetupTransport(ctx)
		uc.rebootstrap.Store(rebootstrapNotStarted)
	}
}

// HTTP/2 health check for DoH connections: after dohSendPingTimeout without a
// received frame, send a PING; close the connection if no reply arrives within
// dohPingTimeout. Variables only so tests can shorten them.
var (
	dohSendPingTimeout = 10 * time.Second
	dohPingTimeout     = 5 * time.Second
)

func (uc *UpstreamConfig) newDOHTransport(ctx context.Context, addrs []string) *http.Transport {
	if uc.Type != ResolverTypeDOH {
		return nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 100
	transport.TLSClientConfig = &tls.Config{
		RootCAs:            uc.certPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		MinVersion:         tls.VersionTLS12,
	}

	// Prevent bad tcp connection hanging the requests for too long.
	// See: https://github.com/golang/go/issues/36026
	transport.HTTP2 = &http.HTTP2Config{
		SendPingTimeout: dohSendPingTimeout,
		PingTimeout:     dohPingTimeout,
	}

	dialerTimeoutMs := 2000
	if uc.Timeout > 0 && uc.Timeout < dialerTimeoutMs {
		dialerTimeoutMs = uc.Timeout
	}
	dialerTimeout := time.Duration(dialerTimeoutMs) * time.Millisecond
	logger := LoggerFromCtx(ctx)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if uc.BootstrapIP != "" {
			dialer := net.Dialer{Timeout: dialerTimeout, KeepAlive: dialerTimeout}
			addr := net.JoinHostPort(uc.BootstrapIP, port)
			Log(ctx, logger.Debug(), "Sending doh request to: %s", addr)
			return dialer.DialContext(ctx, network, addr)
		}
		pd := &ctrldnet.ParallelDialer{}
		pd.Timeout = dialerTimeout
		pd.KeepAlive = dialerTimeout
		conn, err := pd.DialContext(ctx, network, joinHostPorts(addrs, port), logger.Logger)
		if err != nil {
			direct := uc.directFallbackIPs()
			if len(direct) == 0 {
				return nil, err
			}
			Log(ctx, logger.Debug().Err(err), "Bootstrap addresses failed, dialing direct ips %v", direct)
			var directErr error
			if conn, directErr = pd.DialContext(ctx, network, joinHostPorts(direct, port), logger.Logger); directErr != nil {
				return nil, errors.Join(err, directErr)
			}
		}
		Log(ctx, logger.Debug(), "Sending doh request to: %s", conn.RemoteAddr())
		return conn, nil
	}
	runtime.SetFinalizer(transport, func(transport *http.Transport) {
		transport.CloseIdleConnections()
	})
	return transport
}

// Ping warms up the connection to DoH/DoH3 upstream.
func (uc *UpstreamConfig) Ping(ctx context.Context) {
	if err := uc.ping(ctx); err != nil {
		logger := LoggerFromCtx(ctx)
		logger.Debug().Err(err).Msgf("Upstream ping failed: %s", uc.Endpoint)
		_ = uc.FallbackToDirectIP(ctx)
	}
}

// ErrorPing is like Ping, but return an error if any.
func (uc *UpstreamConfig) ErrorPing(ctx context.Context) error {
	return uc.ping(ctx)
}

func (uc *UpstreamConfig) ping(ctx context.Context) error {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3, ResolverTypeDOQ:
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
			if err := ping(uc.dohTransport(ctx, typ)); err != nil {
				return err
			}
		case ResolverTypeDOH3:
			if err := ping(uc.doh3Transport(ctx, typ)); err != nil {
				return err
			}
		case ResolverTypeDOQ:
			// For DoQ, we just ensure transport is set up by calling doqTransport
			// DoQ doesn't use HTTP, so we can't ping it the same way
			_ = uc.doqTransport(ctx, typ)
		case ResolverTypeDOT:
			// For DoT, we just ensure transport is set up by calling dotTransport
			// DoT doesn't use HTTP, so we can't ping it the same way
			_ = uc.dotTransport(ctx, typ)
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

// isNextDNS reports whether this is a NextDNS upstream.
func (uc *UpstreamConfig) isNextDNS() bool {
	domain := uc.Domain
	if domain == "" {
		if u, err := url.Parse(uc.Endpoint); err == nil {
			domain = u.Hostname()
		}
	}
	return dns.IsSubDomain(nextDNSDomain, domain)
}

func (uc *UpstreamConfig) dohTransport(ctx context.Context, dnsType uint16) http.RoundTripper {
	uc.ensureSetupTransport(ctx)
	return transportByIpStack(uc.IPStack, dnsType, uc.transport, uc.transport4, uc.transport6)
}

func (uc *UpstreamConfig) netForDNSType(ctx context.Context, dnsType uint16) (string, string) {
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
			if HasIPv6(ctx) {
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

// controlDDirectIPsFn returns the direct IPs of a Control D domain. It is a
// variable so tests can point the fallback at local listeners.
var controlDDirectIPsFn = bootstrapIPsFromControlDDomain

// directFallbackIPs returns the Control D direct IPs that DoH and DoH3 try
// when the bootstrap addresses fail, once FallbackToDirectIP has fired, or nil.
// They are limited to the families the ip_stack dials: an IPv6-only upstream
// must not be sent to an IPv4 literal it cannot reach.
func (uc *UpstreamConfig) directFallbackIPs() []string {
	if !uc.directFallback.Load() {
		return nil
	}
	ips4, ips6 := splitAddressFamilies(controlDDirectIPsFn(uc.Domain))
	switch uc.IPStack {
	case IpStackV4:
		return ips4
	case IpStackV6:
		return ips6
	}
	return append(ips4, ips6...)
}

// joinHostPorts returns ips joined with port.
func joinHostPorts(ips []string, port string) []string {
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = net.JoinHostPort(ip, port)
	}
	return addrs
}

// FallbackToDirectIP lets a ControlD DoH/DoH3 upstream also dial its direct
// IPs, which DoH and DoH3 try only when the bootstrap addresses are empty or
// all fail. The bootstrap list keeps precedence, so a working or refreshed
// list is used again as soon as it can be, and nothing is pinned. The request
// URL keeps the domain, so TLS still verifies the certificate for it.
func (uc *UpstreamConfig) FallbackToDirectIP(ctx context.Context) bool {
	if !uc.IsControlD() {
		return false
	}
	if uc.u == nil || uc.Domain == "" {
		return false
	}

	done := false
	uc.fallbackOnce.Do(func() {
		ips := controlDDirectIPsFn(uc.Domain)
		if len(ips) == 0 {
			return
		}
		logger := LoggerFromCtx(ctx)
		Log(ctx, logger.Warn(), "Falling back to direct ips for %q when its bootstrap addresses fail: %v", uc.Endpoint, ips)
		uc.directFallback.Store(true)
		done = true
	})
	return done
}

// Init initialized necessary values for an ListenerConfig.
func (lc *ListenerConfig) Init() {
	logger := LoggerFromCtx(context.Background())
	Log(context.Background(), logger.Debug(), "Initializing listener config")

	if lc.Policy != nil {
		lc.Policy.FailoverRcodeNumbers = make([]int, len(lc.Policy.FailoverRcodes))
		for i, rcode := range lc.Policy.FailoverRcodes {
			lc.Policy.FailoverRcodeNumbers[i] = dnsrcode.FromString(rcode)
		}
		Log(context.Background(), logger.Debug(), "Listener policy initialized with %d failover rcodes", len(lc.Policy.FailoverRcodes))
	}

	Log(context.Background(), logger.Debug(), "Listener config initialization completed")
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

// upstreamUID generates an unique identifier for an upstream.
func upstreamUID(ctx context.Context) string {
	logger := LoggerFromCtx(ctx)
	b := make([]byte, 4)
	for {
		if _, err := crand.Read(b); err != nil {
			logger.Warn().Err(err).Msg("Could not generate uid for upstream, retrying...")
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

func transportByIpStack[T any](ipStack string, dnsType uint16, transport, transport4, transport6 T) T {
	switch ipStack {
	case IpStackBoth, IpStackV4, IpStackV6:
		return transport
	case IpStackSplit:
		switch dnsType {
		case dns.TypeA:
			return transport4
		default:
			return transport6
		}
	}
	return transport
}

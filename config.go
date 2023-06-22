package ctrld

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"
	"tailscale.com/logtail/backoff"

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

	controlDComDomain = "controld.com"
	controlDNetDomain = "controld.net"
	controlDDevDomain = "controld.dev"
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
			IP:   "127.0.0.1",
			Port: 53,
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
			BootstrapIP: "76.76.2.11",
			Name:        "Control D - Anti-Malware",
			Type:        ResolverTypeDOH,
			Endpoint:    "https://freedns.controld.com/p1",
			Timeout:     5000,
		},
		"1": {
			BootstrapIP: "76.76.2.11",
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

// ServiceConfig specifies the general ctrld config.
type ServiceConfig struct {
	LogLevel              string `mapstructure:"log_level" toml:"log_level,omitempty"`
	LogPath               string `mapstructure:"log_path" toml:"log_path,omitempty"`
	CacheEnable           bool   `mapstructure:"cache_enable" toml:"cache_enable,omitempty"`
	CacheSize             int    `mapstructure:"cache_size" toml:"cache_size,omitempty"`
	CacheTTLOverride      int    `mapstructure:"cache_ttl_override" toml:"cache_ttl_override,omitempty"`
	CacheServeStale       bool   `mapstructure:"cache_serve_stale" toml:"cache_serve_stale,omitempty"`
	MaxConcurrentRequests *int   `mapstructure:"max_concurrent_requests" toml:"max_concurrent_requests,omitempty" validate:"omitempty,gte=0"`
	Daemon                bool   `mapstructure:"-" toml:"-"`
	AllocateIP            bool   `mapstructure:"-" toml:"-"`
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
	Type        string `mapstructure:"type" toml:"type,omitempty" validate:"oneof=doh doh3 dot doq os legacy"`
	Endpoint    string `mapstructure:"endpoint" toml:"endpoint,omitempty" validate:"required_unless=Type os"`
	BootstrapIP string `mapstructure:"bootstrap_ip" toml:"bootstrap_ip,omitempty"`
	Domain      string `mapstructure:"-" toml:"-"`
	IPStack     string `mapstructure:"ip_stack" toml:"ip_stack,omitempty" validate:"ipstack"`
	Timeout     int    `mapstructure:"timeout" toml:"timeout,omitempty" validate:"gte=0"`
	// The caller should not access this field directly.
	// Use UpstreamSendClientInfo instead.
	SendClientInfo *bool `mapstructure:"send_client_info" toml:"send_client_info,omitempty"`

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
}

// ListenerConfig specifies the networks configuration that ctrld will run on.
type ListenerConfig struct {
	IP         string                `mapstructure:"ip" toml:"ip,omitempty" validate:"iporempty"`
	Port       int                   `mapstructure:"port" toml:"port,omitempty" validate:"gte=0"`
	Restricted bool                  `mapstructure:"restricted" toml:"restricted,omitempty"`
	Policy     *ListenerPolicyConfig `mapstructure:"policy" toml:"policy,omitempty"`
}

// ListenerPolicyConfig specifies the policy rules for ctrld to filter incoming requests.
type ListenerPolicyConfig struct {
	Name                 string   `mapstructure:"name" toml:"name,omitempty"`
	Networks             []Rule   `mapstructure:"networks" toml:"networks,omitempty,inline,multiline" validate:"dive,len=1"`
	Rules                []Rule   `mapstructure:"rules" toml:"rules,omitempty,inline,multiline" validate:"dive,len=1"`
	FailoverRcodes       []string `mapstructure:"failover_rcodes" toml:"failover_rcodes,omitempty" validate:"dive,dnsrcode"`
	FailoverRcodeNumbers []int    `mapstructure:"-" toml:"-"`
}

// Rule is a map from source to list of upstreams.
// ctrld uses rule to perform requests matching and forward
// the request to corresponding upstreams if it's matched.
type Rule map[string][]string

// Init initialized necessary values for an UpstreamConfig.
func (uc *UpstreamConfig) Init() {
	if u, err := url.Parse(uc.Endpoint); err == nil {
		uc.Domain = u.Host
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
		if uc.isControlD() {
			uc.IPStack = IpStackSplit
		} else {
			uc.IPStack = IpStackBoth
		}
	}
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
		if uc.isControlD() {
			return true
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

// SetupBootstrapIP manually find all available IPs of the upstream.
// The first usable IP will be used as bootstrap IP of the upstream.
func (uc *UpstreamConfig) SetupBootstrapIP() {
	uc.setupBootstrapIP(true)
}

// SetupBootstrapIP manually find all available IPs of the upstream.
// The first usable IP will be used as bootstrap IP of the upstream.
func (uc *UpstreamConfig) setupBootstrapIP(withBootstrapDNS bool) {
	b := backoff.NewBackoff("setupBootstrapIP", func(format string, args ...any) {}, 2*time.Second)
	for {
		uc.bootstrapIPs = lookupIP(uc.Domain, uc.Timeout, withBootstrapDNS)
		if len(uc.bootstrapIPs) > 0 {
			break
		}
		ProxyLog.Warn().Msg("could not resolve bootstrap IPs, retrying...")
		b.BackOff(context.Background(), errors.New("no bootstrap IPs"))
	}
	for _, ip := range uc.bootstrapIPs {
		if ctrldnet.IsIPv6(ip) {
			uc.bootstrapIPs6 = append(uc.bootstrapIPs6, ip)
		} else {
			uc.bootstrapIPs4 = append(uc.bootstrapIPs4, ip)
		}
	}
	ProxyLog.Debug().Msgf("Bootstrap IPs: %v", uc.bootstrapIPs)
}

// ReBootstrap re-setup the bootstrap IP and the transport.
func (uc *UpstreamConfig) ReBootstrap() {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3:
	default:
		return
	}
	_, _, _ = uc.g.Do("ReBootstrap", func() (any, error) {
		ProxyLog.Debug().Msg("re-bootstrapping upstream ip")
		uc.rebootstrap.Store(true)
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
		if hasIPv6() {
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
			Log(ctx, ProxyLog.Debug(), "sending doh request to: %s", addr)
			return dialer.DialContext(ctx, network, addr)
		}
		pd := &ctrldnet.ParallelDialer{}
		pd.Timeout = dialerTimeout
		pd.KeepAlive = dialerTimeout
		dialAddrs := make([]string, len(addrs))
		for i := range addrs {
			dialAddrs[i] = net.JoinHostPort(addrs[i], port)
		}
		conn, err := pd.DialContext(ctx, network, dialAddrs)
		if err != nil {
			return nil, err
		}
		Log(ctx, ProxyLog.Debug(), "sending doh request to: %s", conn.RemoteAddr())
		return conn, nil
	}
	runtime.SetFinalizer(transport, func(transport *http.Transport) {
		transport.CloseIdleConnections()
	})
	return transport
}

// Ping warms up the connection to DoH/DoH3 upstream.
func (uc *UpstreamConfig) Ping() {
	switch uc.Type {
	case ResolverTypeDOH, ResolverTypeDOH3:
	default:
		return
	}

	ping := func(t http.RoundTripper) {
		if t == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "HEAD", uc.Endpoint, nil)
		resp, _ := t.RoundTrip(req)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		ping(uc.dohTransport(typ))
		ping(uc.doh3Transport(typ))
	}
}

func (uc *UpstreamConfig) isControlD() bool {
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
			if hasIPv6() {
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
			if hasIPv6() {
				return "tcp6-tls", "udp6"
			}
			return "tcp4-tls", "udp4"
		}
	}
	return "tcp-tls", "udp"
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
// - For anything else -> ResolverTypeDOT
func ResolverTypeFromEndpoint(endpoint string) string {
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return ResolverTypeDOH
	case strings.HasPrefix(endpoint, "quic://"):
		return ResolverTypeDOQ
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

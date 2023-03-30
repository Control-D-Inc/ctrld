package ctrld

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"

	"github.com/Control-D-Inc/ctrld/internal/dnsrcode"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

// SetConfigName set the config name that ctrld will look for.
func SetConfigName(v *viper.Viper, name string) {
	v.SetConfigName(name)

	configPath := "$HOME"
	// viper has its own way to get user home directory:  https://github.com/spf13/viper/blob/v1.14.0/util.go#L134
	// To be consistent, we prefer os.UserHomeDir instead.
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath = homeDir
	}
	v.AddConfigPath(configPath)
	v.AddConfigPath(".")
}

// InitConfig initializes default config values for given *viper.Viper instance.
func InitConfig(v *viper.Viper, name string) {
	SetConfigName(v, name)

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

// ServiceConfig specifies the general ctrld config.
type ServiceConfig struct {
	LogLevel         string `mapstructure:"log_level" toml:"log_level,omitempty"`
	LogPath          string `mapstructure:"log_path" toml:"log_path,omitempty"`
	CacheEnable      bool   `mapstructure:"cache_enable" toml:"cache_enable,omitempty"`
	CacheSize        int    `mapstructure:"cache_size" toml:"cache_size,omitempty"`
	CacheTTLOverride int    `mapstructure:"cache_ttl_override" toml:"cache_ttl_override,omitempty"`
	CacheServeStale  bool   `mapstructure:"cache_serve_stale" toml:"cache_serve_stale,omitempty"`
	Daemon           bool   `mapstructure:"-" toml:"-"`
	AllocateIP       bool   `mapstructure:"-" toml:"-"`
}

// NetworkConfig specifies configuration for networks where ctrld will handle requests.
type NetworkConfig struct {
	Name   string       `mapstructure:"name" toml:"name,omitempty"`
	Cidrs  []string     `mapstructure:"cidrs" toml:"cidrs,omitempty" validate:"dive,cidr"`
	IPNets []*net.IPNet `mapstructure:"-" toml:"-"`
}

// UpstreamConfig specifies configuration for upstreams that ctrld will forward requests to.
type UpstreamConfig struct {
	Name              string            `mapstructure:"name" toml:"name,omitempty"`
	Type              string            `mapstructure:"type" toml:"type,omitempty" validate:"oneof=doh doh3 dot doq os legacy"`
	Endpoint          string            `mapstructure:"endpoint" toml:"endpoint,omitempty" validate:"required_unless=Type os"`
	BootstrapIP       string            `mapstructure:"bootstrap_ip" toml:"bootstrap_ip,omitempty"`
	Domain            string            `mapstructure:"-" toml:"-"`
	Timeout           int               `mapstructure:"timeout" toml:"timeout,omitempty" validate:"gte=0"`
	transport         *http.Transport   `mapstructure:"-" toml:"-"`
	http3RoundTripper http.RoundTripper `mapstructure:"-" toml:"-"`

	g               singleflight.Group
	bootstrapIPs    []string
	nextBootstrapIP atomic.Uint32
}

// ListenerConfig specifies the networks configuration that ctrld will run on.
type ListenerConfig struct {
	IP         string                `mapstructure:"ip" toml:"ip,omitempty" validate:"ip"`
	Port       int                   `mapstructure:"port" toml:"port,omitempty" validate:"gt=0"`
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
	}
	if uc.Domain != "" {
		return
	}

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

// SetupBootstrapIP manually find all available IPs of the upstream.
// The first usable IP will be used as bootstrap IP of the upstream.
func (uc *UpstreamConfig) SetupBootstrapIP() {
	uc.setupBootstrapIP(true)
}

// SetupBootstrapIP manually find all available IPs of the upstream.
// The first usable IP will be used as bootstrap IP of the upstream.
func (uc *UpstreamConfig) setupBootstrapIP(withBootstrapDNS bool) {
	bootstrapIP := func(record dns.RR) string {
		switch ar := record.(type) {
		case *dns.A:
			return ar.A.String()
		case *dns.AAAA:
			return ar.AAAA.String()
		}
		return ""
	}

	resolver := &osResolver{nameservers: availableNameservers()}
	if withBootstrapDNS {
		resolver.nameservers = append([]string{net.JoinHostPort(bootstrapDNS, "53")}, resolver.nameservers...)
	}
	ProxyLog.Debug().Msgf("Resolving %q using bootstrap DNS %q", uc.Domain, resolver.nameservers)
	timeoutMs := 2000
	if uc.Timeout > 0 && uc.Timeout < timeoutMs {
		timeoutMs = uc.Timeout
	}
	do := func(dnsType uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
		m := new(dns.Msg)
		m.SetQuestion(uc.Domain+".", dnsType)
		m.RecursionDesired = true

		r, err := resolver.Resolve(ctx, m)
		if err != nil {
			ProxyLog.Error().Err(err).Str("type", dns.TypeToString[dnsType]).Msgf("could not resolve domain %s for upstream", uc.Domain)
			return
		}
		if r.Rcode != dns.RcodeSuccess {
			ProxyLog.Error().Msgf("could not resolve domain %q, return code: %s", uc.Domain, dns.RcodeToString[r.Rcode])
			return
		}
		if len(r.Answer) == 0 {
			ProxyLog.Error().Msg("no answer from bootstrap DNS server")
			return
		}
		for _, a := range r.Answer {
			ip := bootstrapIP(a)
			if ip == "" {
				continue
			}

			// Storing the ip to uc.bootstrapIPs list, so it can be selected later
			// when retrying failed request due to network stack changed.
			uc.bootstrapIPs = append(uc.bootstrapIPs, ip)
			if uc.BootstrapIP == "" {
				// Remember what's the current IP in bootstrap IPs list,
				// so we can select next one upon re-bootstrapping.
				uc.nextBootstrapIP.Add(1)

				// If this is an ipv6, and ipv6 is not available, don't use it as bootstrap ip.
				if !ctrldnet.SupportsIPv6() && ctrldnet.IsIPv6(ip) {
					continue
				}
				uc.BootstrapIP = ip
			}
		}
	}
	// Find all A, AAAA records of the upstream.
	for _, dnsType := range []uint16{dns.TypeAAAA, dns.TypeA} {
		do(dnsType)
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
		n := uint32(len(uc.bootstrapIPs))
		if n == 0 {
			uc.SetupBootstrapIP()
			uc.setupTransportWithoutPingUpstream()
		}

		timeoutMs := 1000
		if uc.Timeout > 0 && uc.Timeout < timeoutMs {
			timeoutMs = uc.Timeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()

		hasIPv6 := ctrldnet.IPv6Available(ctx)
		// Only attempt n times, because if there's no usable ip,
		// the bootstrap ip will be kept as-is.
		for i := uint32(0); i < n; i++ {
			// Select the next ip in bootstrap ip list.
			next := uc.nextBootstrapIP.Add(1)
			ip := uc.bootstrapIPs[(next-1)%n]
			if !hasIPv6 && ctrldnet.IsIPv6(ip) {
				continue
			}
			uc.BootstrapIP = ip
			break
		}
		uc.setupTransportWithoutPingUpstream()
		return true, nil
	})
}

func (uc *UpstreamConfig) setupTransportWithoutPingUpstream() {
	switch uc.Type {
	case ResolverTypeDOH:
		uc.setupDOHTransportWithoutPingUpstream()
	case ResolverTypeDOH3:
		uc.setupDOH3TransportWithoutPingUpstream()
	}
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
	uc.setupDOHTransportWithoutPingUpstream()
	uc.pingUpstream()
}

func (uc *UpstreamConfig) setupDOHTransportWithoutPingUpstream() {
	uc.transport = http.DefaultTransport.(*http.Transport).Clone()
	uc.transport.IdleConnTimeout = 5 * time.Second

	dialerTimeoutMs := 2000
	if uc.Timeout > 0 && uc.Timeout < dialerTimeoutMs {
		dialerTimeoutMs = uc.Timeout
	}
	dialerTimeout := time.Duration(dialerTimeoutMs) * time.Millisecond
	uc.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   dialerTimeout,
			KeepAlive: dialerTimeout,
		}
		// if we have a bootstrap ip set, use it to avoid DNS lookup
		if uc.BootstrapIP != "" {
			if _, port, _ := net.SplitHostPort(addr); port != "" {
				addr = net.JoinHostPort(uc.BootstrapIP, port)
			}
		}
		Log(ctx, ProxyLog.Debug(), "sending doh request to: %s", addr)
		return dialer.DialContext(ctx, network, addr)
	}
}

func (uc *UpstreamConfig) pingUpstream() {
	// Warming up the transport by querying a test packet.
	dnsResolver, err := NewResolver(uc)
	if err != nil {
		ProxyLog.Error().Err(err).Msgf("failed to create resolver for upstream: %s", uc.Name)
		return
	}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	msg.MsgHdr.RecursionDesired = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = dnsResolver.Resolve(ctx, msg)
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
	return validate.Struct(cfg)
}

func validateDnsRcode(fl validator.FieldLevel) bool {
	return dnsrcode.FromString(fl.Field().String()) != -1
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

func availableNameservers() []string {
	nss := nameservers()
	n := 0
	for _, ns := range nss {
		ip, _, _ := net.SplitHostPort(ns)
		// skipping invalid entry or ipv6 nameserver if ipv6 not available.
		if ip == "" || (ctrldnet.IsIPv6(ip) && !ctrldnet.SupportsIPv6()) {
			continue
		}
		nss[n] = ns
		n++
	}
	return nss[:n]
}

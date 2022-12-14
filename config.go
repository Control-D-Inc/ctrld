package ctrld

import (
	"net"
	"net/url"
	"strings"

	"github.com/Control-D-Inc/ctrld/internal/dnsrcode"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// InitConfig initializes default config values for given *viper.Viper instance.
func InitConfig(v *viper.Viper, name string) {
	v.SetConfigName(name)
	v.SetConfigType("toml")
	v.AddConfigPath("$HOME/.ctrld")
	v.AddConfigPath(".")

	v.SetDefault("service", ServiceConfig{
		LogLevel: "info",
	})
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
			Type:        "doh",
			Endpoint:    "https://freedns.controld.com/p1",
			Timeout:     5000,
		},
		"1": {
			BootstrapIP: "76.76.2.11",
			Name:        "Control D - No Ads",
			Type:        "doq",
			Endpoint:    "p2.freedns.controld.com",
			Timeout:     3000,
		},
	})
}

// Config represents ctrld supported configuration.
type Config struct {
	Service  ServiceConfig              `mapstructure:"service"`
	Network  map[string]*NetworkConfig  `mapstructure:"network" toml:"network" validate:"min=1,dive"`
	Upstream map[string]*UpstreamConfig `mapstructure:"upstream" toml:"upstream" validate:"min=1,dive"`
	Listener map[string]*ListenerConfig `mapstructure:"listener" toml:"listener" validate:"min=1,dive"`
}

// ServiceConfig specifies the general ctrld config.
type ServiceConfig struct {
	LogLevel   string `mapstructure:"log_level" toml:"log_level"`
	LogPath    string `mapstructure:"log_path" toml:"log_path"`
	Daemon     bool   `mapstructure:"-" toml:"-"`
	AllocateIP bool   `mapstructure:"-" toml:"-"`
}

// NetworkConfig specifies configuration for networks where ctrld will handle requests.
type NetworkConfig struct {
	Name   string       `mapstructure:"name" toml:"name"`
	Cidrs  []string     `mapstructure:"cidrs" toml:"cidrs" validate:"dive,cidr"`
	IPNets []*net.IPNet `mapstructure:"-" toml:"-"`
}

// UpstreamConfig specifies configuration for upstreams that ctrld will forward requests to.
type UpstreamConfig struct {
	Name        string `mapstructure:"name" toml:"name"`
	Type        string `mapstructure:"type" toml:"type" validate:"oneof=doh doh3 dot doq os legacy"`
	Endpoint    string `mapstructure:"endpoint" toml:"endpoint" validate:"required_unless=Type os"`
	BootstrapIP string `mapstructure:"bootstrap_ip" toml:"bootstrap_ip"`
	Domain      string `mapstructure:"-" toml:"-"`
	Timeout     int    `mapstructure:"timeout" toml:"timeout" validate:"gte=0"`
}

// ListenerConfig specifies the networks configuration that ctrld will run on.
type ListenerConfig struct {
	IP         string                `mapstructure:"ip" toml:"ip" validate:"ip"`
	Port       int                   `mapstructure:"port" toml:"port" validate:"gt=0"`
	Restricted bool                  `mapstructure:"restricted" toml:"restricted"`
	Policy     *ListenerPolicyConfig `mapstructure:"policy" toml:"policy"`
}

// ListenerPolicyConfig specifies the policy rules for ctrld to filter incoming requests.
type ListenerPolicyConfig struct {
	Name                 string   `mapstructure:"name" toml:"name"`
	Networks             []Rule   `mapstructure:"networks" toml:"networks" validate:"dive,len=1"`
	Rules                []Rule   `mapstructure:"rules" toml:"rules" validate:"dive,len=1"`
	FailoverRcodes       []string `mapstructure:"failover_rcodes" toml:"failover_rcodes" validate:"dive,dnsrcode"`
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
	case resolverTypeDOH, resolverTypeDOH3:
		return "443"
	case resolverTypeDOQ, resolverTypeDOT:
		return "853"
	case resolverTypeLegacy:
		return "53"
	}
	return "53"
}

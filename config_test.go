package ctrld_test

import (
	"os"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

func TestLoadConfig(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	validate := validator.New()
	require.NoError(t, ctrld.ValidateConfig(validate, cfg))

	assert.Equal(t, "info", cfg.Service.LogLevel)
	assert.Equal(t, "/path/to/log.log", cfg.Service.LogPath)

	assert.Len(t, cfg.Network, 2)
	assert.Contains(t, cfg.Network, "0")
	assert.Contains(t, cfg.Network, "1")

	assert.Len(t, cfg.Upstream, 4)
	assert.Contains(t, cfg.Upstream, "0")
	assert.Contains(t, cfg.Upstream, "1")
	assert.Contains(t, cfg.Upstream, "2")
	assert.Contains(t, cfg.Upstream, "3")
	assert.NotNil(t, cfg.Upstream["3"].SendClientInfo)

	assert.Len(t, cfg.Listener, 2)
	assert.Contains(t, cfg.Listener, "0")
	assert.Contains(t, cfg.Listener, "1")

	require.NotNil(t, cfg.Listener["0"].Policy)
	assert.Equal(t, "My Policy", cfg.Listener["0"].Policy.Name)
	require.NotNil(t, cfg.Listener["0"].Policy.Networks)
	assert.Len(t, cfg.Listener["0"].Policy.Networks, 3)

	require.NotNil(t, cfg.Listener["0"].Policy.Rules)
	assert.Len(t, cfg.Listener["0"].Policy.Rules, 2)
	assert.Contains(t, cfg.Listener["0"].Policy.Rules[0], "*.ru")
	assert.Contains(t, cfg.Listener["0"].Policy.Rules[1], "*.local.host")

	assert.True(t, cfg.HasUpstreamSendClientInfo())
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg := defaultConfig(t)
	validate := validator.New()
	require.NoError(t, ctrld.ValidateConfig(validate, cfg))
	if assert.Len(t, cfg.Listener, 1) {
		l0 := cfg.Listener["0"]
		require.NotNil(t, l0.Policy)
		assert.Len(t, l0.Policy.Networks, 1)
		assert.Len(t, l0.Policy.Rules, 2)
	}
	assert.Len(t, cfg.Upstream, 2)
}

func TestConfigOverride(t *testing.T) {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "test_load_config")
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(testhelper.SampleConfigStr(t))))
	cfg := ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{
		"0": {IP: "127.0.0.1", Port: 53},
	}}
	require.NoError(t, v.Unmarshal(&cfg))

	assert.Equal(t, "10.10.42.69", cfg.Listener["1"].IP)
	assert.Equal(t, 1337, cfg.Listener["1"].Port)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *ctrld.Config
		wantErr bool
	}{
		{"invalid Config", &ctrld.Config{}, true},
		{"default Config", defaultConfig(t), false},
		{"sample Config", testhelper.SampleConfig(t), false},
		{"empty listener IP", emptyListenerIP(t), false},
		{"invalid cidr", invalidNetworkConfig(t), true},
		{"invalid upstream type", invalidUpstreamType(t), true},
		{"invalid upstream timeout", invalidUpstreamTimeout(t), true},
		{"invalid upstream missing endpoint", invalidUpstreamMissingEndpoind(t), true},
		{"invalid listener ip", invalidListenerIP(t), true},
		{"invalid listener port", invalidListenerPort(t), true},
		{"os upstream", configWithOsUpstream(t), false},
		{"invalid rules", configWithInvalidRules(t), true},
		{"invalid dns rcodes", configWithInvalidRcodes(t), true},
		{"invalid max concurrent requests", configWithInvalidMaxConcurrentRequests(t), true},
		{"non-existed lease file", configWithNonExistedLeaseFile(t), true},
		{"lease file format required if lease file exist", configWithExistedLeaseFile(t), true},
		{"invalid lease file format", configWithInvalidLeaseFileFormat(t), true},
		{"invalid doh/doh3 endpoint", configWithInvalidDoHEndpoint(t), true},
		{"invalid client id pref", configWithInvalidClientIDPref(t), true},
		{"doh endpoint without scheme", dohUpstreamEndpointWithoutScheme(t), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validate := validator.New()
			err := ctrld.ValidateConfig(validate, tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, but got nil: %+v", tc.cfg)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				t.Logf("%v", err)
			}
		})
	}
}

func TestConfigDiscoverOverride(t *testing.T) {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "test_config_discover_override")
	v.SetConfigType("toml")
	configStr := `
[service]
discover_arp = false
discover_dhcp = false
discover_hosts = false
discover_mdns = false
discover_ptr = false
`
	require.NoError(t, v.ReadConfig(strings.NewReader(configStr)))
	cfg := ctrld.Config{}
	require.NoError(t, v.Unmarshal(&cfg))

	require.False(t, *cfg.Service.DiscoverARP)
	require.False(t, *cfg.Service.DiscoverDHCP)
	require.False(t, *cfg.Service.DiscoverHosts)
	require.False(t, *cfg.Service.DiscoverMDNS)
	require.False(t, *cfg.Service.DiscoverPtr)
}

func defaultConfig(t *testing.T) *ctrld.Config {
	v := viper.New()
	ctrld.InitConfig(v, "test_load_default_config")
	_, ok := v.ReadInConfig().(viper.ConfigFileNotFoundError)
	require.True(t, ok)

	var cfg ctrld.Config
	require.NoError(t, v.Unmarshal(&cfg))
	return &cfg
}

func invalidNetworkConfig(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Network["0"].Cidrs = []string{"172.16.256.255/16", "2001:cdba:0000:0000:0000:0000:3257:9652/256"}
	return cfg
}

func invalidUpstreamType(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["0"].Type = "DOH"
	return cfg
}

func dohUpstreamEndpointWithoutScheme(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["0"].Endpoint = "freedns.controld.com/p1"
	return cfg
}

func invalidUpstreamTimeout(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["0"].Timeout = -1
	return cfg
}

func invalidUpstreamMissingEndpoind(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["0"].Endpoint = ""
	return cfg
}

func invalidListenerIP(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Listener["0"].IP = "invalid ip"
	return cfg
}

func emptyListenerIP(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Listener["0"].IP = ""
	return cfg
}

func invalidListenerPort(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Listener["0"].Port = -1
	return cfg
}

func configWithOsUpstream(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["os"] = &ctrld.UpstreamConfig{
		Name:     "OS",
		Type:     "os",
		Endpoint: "",
	}
	return cfg
}

func configWithInvalidRules(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Listener["0"].Policy = &ctrld.ListenerPolicyConfig{
		Name:     "Invalid Policy",
		Networks: []ctrld.Rule{{"*.com": []string{"upstream.1"}, "*.net": []string{"upstream.0"}}},
		Rules:    nil,
	}
	return cfg
}

func configWithInvalidRcodes(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Listener["0"].Policy = &ctrld.ListenerPolicyConfig{
		Name:           "Policy with invalid Rcodes",
		Networks:       []ctrld.Rule{{"*.com": []string{"upstream.0"}}},
		FailoverRcodes: []string{"foo"},
	}
	return cfg
}

func configWithInvalidMaxConcurrentRequests(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	n := -1
	cfg.Service.MaxConcurrentRequests = &n
	return cfg
}

func configWithNonExistedLeaseFile(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Service.DHCPLeaseFile = "non-existed"
	return cfg
}

func configWithExistedLeaseFile(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Service.DHCPLeaseFile = exe
	return cfg
}

func configWithInvalidLeaseFileFormat(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Service.DHCPLeaseFileFormat = "invalid"
	return cfg
}

func configWithInvalidDoHEndpoint(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Upstream["0"].Endpoint = "/1.1.1.1"
	cfg.Upstream["0"].Type = ctrld.ResolverTypeDOH
	return cfg
}

func configWithInvalidClientIDPref(t *testing.T) *ctrld.Config {
	cfg := defaultConfig(t)
	cfg.Service.ClientIDPref = "foo"
	return cfg
}

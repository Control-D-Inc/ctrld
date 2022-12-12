package testhelper

import (
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func SampleConfig(t *testing.T) *ctrld.Config {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	ctrld.InitConfig(v, "test_load_config")
	require.NoError(t, v.ReadConfig(strings.NewReader(sampleConfigContent)))
	var cfg ctrld.Config
	require.NoError(t, v.Unmarshal(&cfg))
	return &cfg
}

var sampleConfigContent = `
[service]
log_level = "info"
log_path = "/path/to/log.log"

[network.0]
name = "Home Wifi"
cidrs = ["192.168.0.0/24"]

[network.1]
name = "Kids Wifi"
cidrs = ["192.168.1.0/24"]

[upstream.0]
name = "Control D - Standard Devices"
type = "doh"
endpoint = "https://dns.controld.com/12345abcd/main-device"
timeout = 5

[upstream.1]
name = "Control D - Kids Devices"
type = "dot"
endpoint = "12345abcd-kids-devices.dns.controld.com"
timeout = 5

[upstream.2]
name = "Google"
type = "legacy"
endpoint = "8.8.8.8"
timeout = 5

[listener.0]
ip = "127.0.0.1"
port = 53

[listener.1]
ip = "10.10.42.69"
port = 1337

[listener.0.policy]
name = "My Policy"
networks = [
    {"network.0" = ["upstream.1", "upstream.0"]},
    {"network.1" = ["upstream.0"]},
    {"network.2" = ["upstream.1"]},
]

rules = [
    {"*.ru"         = ["upstream.1"]},
    {"*.local.host" = ["upstream.2", "upstream.0"]},
]
`

package cli

import (
	"context"
	"encoding/base64"
	"maps"
	"slices"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// The config error must name the listener key that it rejects, so that an
// operator can find it in the config.
func TestFieldErrorMsgListenerKey(t *testing.T) {
	cfg := &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"01": {}}}

	err := ctrld.ValidateConfig(validator.New(), cfg)

	var errs validator.ValidationErrors
	require.ErrorAs(t, err, &errs)
	for _, fe := range errs {
		if fe.Tag() == "listenerkey" {
			require.Equal(t, `listener key must be a number such as 0 or 1, with no sign or leading zero: "01"`, fieldErrorMsg(fe))
			require.Equal(t, "Config.Listener[01]", fe.Namespace())
			return
		}
	}
	t.Fatalf("no listenerkey error in %v", err)
}

// The API can send a custom config with any listener key. A start must
// disregard all of a config that it cannot use, and go on with the generated
// config.
func TestProcessCDFlagsDisregardsCustomConfigWithUnusableListenerKey(t *testing.T) {
	oldFetch, oldUID, oldMetadata := fetchResolverConfig, cdUID, startupMetadata
	t.Cleanup(func() { fetchResolverConfig, cdUID, startupMetadata = oldFetch, oldUID, oldMetadata })
	cdUID = "testuid"
	startupMetadata = func(context.Context) map[string]string { return nil }
	const custom = "[service]\nlog_level = \"debug\"\n\n[network.7]\nname = \"from custom\"\ncidrs = [\"10.0.0.0/8\"]\n\n[listener.01]\nip = \"127.0.0.1\"\nport = 5399\n\n[upstream.0]\ntype = \"doh\"\nendpoint = \"https://dns.controld.com/testuid\"\ntimeout = 5000\n"
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		rc := &controld.ResolverConfig{DOH: "https://dns.controld.com/testuid"}
		rc.Ctrld.CustomConfig = base64.StdEncoding.EncodeToString([]byte(custom))
		return rc, nil
	}
	cfg := ctrld.Config{}

	_, err := processCDFlags(context.Background(), &cfg)

	require.NoError(t, err)
	require.Equal(t, []string{"0"}, slices.Sorted(maps.Keys(cfg.Listener)))
	require.NotContains(t, cfg.Network, "7")
	require.Empty(t, cfg.Service.LogLevel)
}

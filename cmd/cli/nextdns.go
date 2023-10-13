package cli

import (
	"fmt"

	"github.com/Control-D-Inc/ctrld"
)

const nextdnsURL = "https://dns.nextdns.io"

func generateNextDNSConfig() {
	if nextdns == "" {
		return
	}
	mainLog.Load().Info().Msg("generating ctrld config for NextDNS resolver")
	cfg = ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{
			"0": {
				IP:   "0.0.0.0",
				Port: 53,
			},
		},
		Upstream: map[string]*ctrld.UpstreamConfig{
			"0": {
				Type:     ctrld.ResolverTypeDOH3,
				Endpoint: fmt.Sprintf("%s/%s", nextdnsURL, nextdns),
				Timeout:  5000,
			},
		},
	}
}

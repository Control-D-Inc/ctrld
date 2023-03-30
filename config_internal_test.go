package ctrld

import (
	"testing"
)

func TestUpstreamConfig_SetupBootstrapIP(t *testing.T) {
	uc := &UpstreamConfig{
		Name:     "test",
		Type:     ResolverTypeDOH,
		Endpoint: "https://freedns.controld.com/p2",
		Timeout:  5000,
	}
	uc.Init()
	uc.setupBootstrapIP(false)
	if uc.BootstrapIP == "" {
		t.Fatal("could not bootstrap ip without bootstrap DNS")
	}
	t.Log(uc)
}

package cli

import (
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func stubAppConfigGlobals(t *testing.T) *[]int64 {
	t.Helper()
	oldDev, oldLimit := cdDev, setMemoryLimit
	oldUID, oldOrg, oldHost, oldHome, oldProto, oldVerbose, oldLogPath := cdUID, cdOrg, customHostname, homedir, cdUpstreamProto, verbose, logPath
	oldConfigFile := defaultConfigFile
	var limits []int64
	setMemoryLimit = func(limit int64) int64 { limits = append(limits, limit); return 0 }
	t.Cleanup(func() {
		cdDev, setMemoryLimit = oldDev, oldLimit
		cdUID, cdOrg, customHostname, homedir, cdUpstreamProto, verbose, logPath = oldUID, oldOrg, oldHost, oldHome, oldProto, oldVerbose, oldLogPath
		defaultConfigFile = oldConfigFile
		ctrld.SetAppNameservers(nil)
		storeLogSecrets()
	})
	return &limits
}

func TestApplyAppConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     AppConfig
		wantDev    bool
		wantLimits []int64
		wantNss    []string
	}{
		{"dev", AppConfig{Dev: true}, true, nil, nil},
		{"memory limit", AppConfig{MemoryLimitMiB: 48}, false, []int64{48 << 20}, nil},
		{"nameservers", AppConfig{Nameservers: "192.168.1.1, 2606:4700::1111"}, false, nil, []string{"192.168.1.1", "2606:4700::1111"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limits := stubAppConfigGlobals(t)
			applyAppConfig(&tc.config)
			if cdDev != tc.wantDev {
				t.Errorf("cdDev = %v, want %v", cdDev, tc.wantDev)
			}
			if !slices.Equal(*limits, tc.wantLimits) {
				t.Errorf("memory limits = %v, want %v", *limits, tc.wantLimits)
			}
			if got := ctrld.AppNameservers(); !slices.Equal(got, tc.wantNss) {
				t.Errorf("app nameservers = %v, want %v", got, tc.wantNss)
			}
		})
	}
}

// The library runs many times in one process. A run must not inherit the
// dev API or the nameservers of the run before it.
func TestApplyAppConfigResetsEarlierRun(t *testing.T) {
	stubAppConfigGlobals(t)
	applyAppConfig(&AppConfig{Dev: true, Nameservers: "192.168.1.1"})
	applyAppConfig(&AppConfig{})
	if cdDev {
		t.Error("the dev API of the earlier run stayed on")
	}
	if got := ctrld.AppNameservers(); got != nil {
		t.Errorf("the nameservers of the earlier run stayed: %v", got)
	}
}

// The provision token and the custom hostname are inputs of one run, so a
// run without them must not use the values of the run before it.
func TestApplyAppConfigResetsTokenAndHostname(t *testing.T) {
	stubAppConfigGlobals(t)
	applyAppConfig(&AppConfig{ProvisionID: "org-v1-abcdef", CustomHostname: "phone"})
	applyAppConfig(&AppConfig{})
	if cdOrg != "" {
		t.Errorf("cdOrg = %q, want the token of the earlier run gone", cdOrg)
	}
	if customHostname != "" {
		t.Errorf("customHostname = %q, want the hostname of the earlier run gone", customHostname)
	}
}

// A token exchange sets cdUID during the run. The next run with the same
// token must use that UID, or it exchanges the token again and the API makes
// a new device.
func TestApplyAppConfigKeepsExchangedUID(t *testing.T) {
	stubAppConfigGlobals(t)
	applyAppConfig(&AppConfig{ProvisionID: "org-v1-abcdef"})
	cdUID = "exchanged-uid"
	applyAppConfig(&AppConfig{ProvisionID: "org-v1-abcdef"})
	if cdUID != "exchanged-uid" {
		t.Errorf("cdUID = %q, want the UID of the token exchange", cdUID)
	}
	applyAppConfig(&AppConfig{CdUID: "app-uid"})
	if cdUID != "app-uid" {
		t.Errorf("cdUID = %q, want the UID that the app sends", cdUID)
	}
}

// Start replaces a list that SetMobileNameservers set before the run, so a
// run never inherits the network of an earlier run.
func TestApplyAppConfigReplacesSetNameservers(t *testing.T) {
	stubAppConfigGlobals(t)
	SetMobileNameservers("192.168.255.53")
	applyAppConfig(&AppConfig{})
	if got := ctrld.AppNameservers(); got != nil {
		t.Errorf("app nameservers = %v, want none", got)
	}
}

func TestSetMobileNameserversRebuildsOsResolver(t *testing.T) {
	stubAppConfigGlobals(t)
	SetMobileNameservers("192.168.255.53")
	if got := ctrld.OsResolverNameservers(); !slices.Contains(got, "192.168.255.53:53") {
		t.Fatalf("OS resolver nameservers = %v, want the app nameserver", got)
	}
	// With no network, the app reports none. A list with no IP address is
	// the same as no list. The last known list stays.
	for _, csv := range []string{"", "not-an-ip", "192.168.1.1:53", " , "} {
		SetMobileNameservers(csv)
		if got := ctrld.OsResolverNameservers(); !slices.Contains(got, "192.168.255.53:53") {
			t.Fatalf("the list %q replaced the OS resolver: %v", csv, got)
		}
		if got := ctrld.AppNameservers(); !slices.Equal(got, []string{"192.168.255.53"}) {
			t.Fatalf("the list %q replaced the app nameservers: %v", csv, got)
		}
	}
}

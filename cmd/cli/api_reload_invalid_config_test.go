package cli

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// The warning for an invalid custom config must name the cause. The fetch
// error is nil on this path, so a warning with it says nothing.
func TestAPIReloadLogsWhyTheCustomConfigIsInvalid(t *testing.T) {
	// A fetch that succeeds stores these.
	oldPin, oldKnown, oldTarget := cdDeactivationPin.Load(), deactivationPinKnown.Load(), cdVersionTarget.Load()
	oldReport := updateCustomLastFailed
	t.Cleanup(func() {
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
		cdVersionTarget.Store(oldTarget)
		updateCustomLastFailed = oldReport
	})
	stubReload(t, false, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		rc := &controld.ResolverConfig{}
		rc.Ctrld.CustomConfig = "not base64!"
		return rc, nil
	})
	reported := make(chan struct{}, 1)
	updateCustomLastFailed = func(context.Context, string, string, bool, bool) (*controld.ResolverConfig, error) {
		select {
		case reported <- struct{}{}:
		default:
		}
		return nil, nil
	}
	runLog := captureMainLog(t)

	p := newReloadRun(nil)
	startReload(t, p)
	forceReload(t, p)
	select {
	case <-reported:
	case <-time.After(5 * time.Second):
		t.Fatal("the invalid custom config was not reported to the API")
	}
	var warning string
	for _, line := range strings.Split(runLog.String(), "\n") {
		if strings.Contains(line, "skipping invalid custom config") {
			warning = line
		}
	}
	require.Contains(t, warning, "invalid base64 config", "the warning must name why the custom config is invalid")
}

// The validation of a restart must also name why the custom config is
// invalid. The fetch error is nil on this path too.
func TestRestartValidationLogsWhyTheCustomConfigIsInvalid(t *testing.T) {
	stubProvisionGlobals(t)
	oldFetch := fetchResolverConfig
	t.Cleanup(func() { fetchResolverConfig = oldFetch })
	tests := []struct {
		name         string
		customConfig string
		wantCause    string
	}{
		{"not base64", "not base64!", "invalid base64 config"},
		{"rule of the config broken", base64.StdEncoding.EncodeToString([]byte("[upstream.0]\ntype = \"bogus\"\nendpoint = \"127.0.0.1\"\n")), "Upstream[0].Type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
				rc := &controld.ResolverConfig{}
				rc.Ctrld.CustomConfig = tc.customConfig
				return rc, nil
			}
			runLog := captureMainLog(t)
			require.NoError(t, doValidateCdRemoteConfig("device-uid-123", false))
			var warning string
			for _, line := range strings.Split(runLog.String(), "\n") {
				if strings.Contains(line, "disregarding invalid custom config") {
					warning = line
				}
			}
			require.Contains(t, warning, tc.wantCause, "the warning must name why the custom config is invalid")
			require.NotContains(t, runLog.String(), "<nil>")
		})
	}
}

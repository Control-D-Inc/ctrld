package cli

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// TestMaintenanceFallbackFirewallAllowedDestinations covers Firewall Mode on a
// maintenance fallback start. The organization's Allowed Destinations exist
// only in the API answer, which such a run does not have, so the exception set
// is empty until the API returns. That is a deliberate fail-closed state: it
// must be named in the retained journal, and the first answer after recovery
// must re-apply the list even though nothing else is compared as changed.
func TestMaintenanceFallbackFirewallAllowedDestinations(t *testing.T) {
	allowed := netip.MustParseAddr("203.0.113.10")

	t.Run("fallback start journals that allowed destinations are not enforced", func(t *testing.T) {
		logs := captureDebugMainLog(t)
		p := progWithAllowList()
		p.logger.Store(mainLog.Load())
		p.startedInAPIMaintenance.Store(true)

		p.syncAllowedDestinations()

		events := jsonLogEvents(t, logs, "Firewall: organization allowed destinations are not enforced until the Control D API answers; started on the configuration on disk during maintenance")
		if len(events) != 1 {
			t.Fatalf("fail-closed warnings: got %d, want 1", len(events))
		}
		if events[0]["level"] != "warn" {
			t.Errorf("level = %v, want warn", events[0]["level"])
		}
		if events[0]["reason"] != "api_maintenance" {
			t.Errorf("reason = %v, want api_maintenance", events[0]["reason"])
		}
		if events[0]["journal"] != true {
			t.Error("the fail-closed warning is not retained in the journal")
		}
		if p.allowList.Contains(allowed) {
			t.Fatalf("%s allowed with no resolver config", allowed)
		}
	})

	t.Run("a normal start with no resolver config stays quiet", func(t *testing.T) {
		logs := captureDebugMainLog(t)
		p := progWithAllowList()
		p.logger.Store(mainLog.Load())

		p.syncAllowedDestinations()

		if got := len(jsonLogEvents(t, logs, "Firewall: organization allowed destinations are not enforced until the Control D API answers; started on the configuration on disk during maintenance")); got != 0 {
			t.Fatalf("fail-closed warnings outside maintenance: got %d, want 0", got)
		}
	})

	t.Run("firewall mode off stays quiet", func(t *testing.T) {
		logs := captureDebugMainLog(t)
		p := &prog{}
		p.logger.Store(mainLog.Load())
		p.startedInAPIMaintenance.Store(true)

		p.syncAllowedDestinations()

		if got := len(jsonLogEvents(t, logs, "Firewall: organization allowed destinations are not enforced until the Control D API answers; started on the configuration on disk during maintenance")); got != 0 {
			t.Fatalf("fail-closed warnings with Firewall Mode off: got %d, want 0", got)
		}
	})

	t.Run("pending recovery re-applies the list", func(t *testing.T) {
		p := progWithAllowList()
		p.apiReloadCh = make(chan *ctrld.Config, 1)
		p.startedInAPIMaintenance.Store(true)
		// The fallback start applied an empty set.
		p.syncAllowedDestinations()
		if p.allowList.Contains(allowed) {
			t.Fatalf("%s allowed before recovery", allowed)
		}

		p.applyFetchedResolverConfig(context.Background(), discardLogger(), &controld.ResolverConfig{
			DestinationIPs: []string{"203.0.113.10"},
		}, false, time.Now().Unix())

		if !p.allowList.Contains(allowed) {
			t.Fatalf("recovery did not re-apply the organization list: %s blocked", allowed)
		}
		select {
		case <-p.apiReloadCh:
		default:
			t.Fatal("pending recovery did not deliver the answer to the apply path")
		}
	})
}

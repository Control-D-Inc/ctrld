//go:build darwin

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// stubHostContextReads replaces every host read behind addHostContext, so the
// test runs no host command, with the NE store returning confs.
func stubHostContextReads(t *testing.T, confs []string) {
	t.Helper()
	prevRule, prevGroup, prevSysext := capturePFGroupRuleFn, lookupCtrldGroupFn, listSystemExtensionsFn
	prevNE, prevVPN, prevKext, prevAnchors := listNEConfigurationsFn, listVPNServicesFn, listThirdPartyKextsFn, listPFAnchorsFn
	capturePFGroupRuleFn = func() pfGroupRuleSnapshot { return pfGroupRuleSnapshot{Code: "ok", GID: "600", Known: true} }
	lookupCtrldGroupFn = func() ([]string, string) { return []string{"600"}, "ok" }
	listSystemExtensionsFn = func() ([]string, []string, string) { return nil, nil, "ok" }
	listNEConfigurationsFn = func() ([]string, string) { return confs, "ok" }
	listVPNServicesFn = func() ([]string, string) { return nil, "ok" }
	listThirdPartyKextsFn = func() ([]string, string) { return nil, "ok" }
	listPFAnchorsFn = func() ([]string, string) { return nil, "ok" }
	t.Cleanup(func() {
		capturePFGroupRuleFn, lookupCtrldGroupFn, listSystemExtensionsFn = prevRule, prevGroup, prevSysext
		listNEConfigurationsFn, listVPNServicesFn, listThirdPartyKextsFn, listPFAnchorsFn = prevNE, prevVPN, prevKext, prevAnchors
	})
}

// captureExemptionContextLog runs logInterceptExemptionContext against a
// fresh JSON logger and returns its events.
func captureExemptionContextLog(t *testing.T) []map[string]any {
	t.Helper()
	buf := &syncBuffer{}
	prev := mainLog.Load()
	mainLog.Store(newTestJSONLogger(buf))
	t.Cleanup(func() { mainLog.Store(prev) })
	logInterceptExemptionContext()
	var events []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) == nil {
			events = append(events, e)
		}
	}
	return events
}

// The customer case behind #659: a Cisco DNS proxy left enabled after its
// app was removed. The start context names it, and one warning says what it
// can break, before any lookup has failed.
func TestExemptionContextWarnsOnForeignDNSProxy(t *testing.T) {
	stubHostContextReads(t, []string{
		"content_filter:com.apple.ALF.ApplicationFirewall:com.apple.ALF.ApplicationFirewall:enabled",
		"dns_proxy:com.cisco.anyconnect.macos.acsock:com.cisco.anyconnect.macos.acsockext:enabled",
	})
	events := captureExemptionContextLog(t)
	if len(events) != 2 {
		t.Fatalf("got %d events, want context + warning: %v", len(events), events)
	}
	ctx, warn := events[0], events[1]
	if !strings.HasPrefix(ctx["message"].(string), "DNS intercept: pf exemption context") {
		t.Fatalf("first event = %v", ctx["message"])
	}
	want := "com.cisco.anyconnect.macos.acsock:com.cisco.anyconnect.macos.acsockext"
	for _, e := range events {
		got, _ := e["dns_proxies_enabled"].([]any)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: dns_proxies_enabled = %v, want [%s]", e["message"], e["dns_proxies_enabled"], want)
		}
	}
	if warn["level"] != "warn" || !strings.Contains(warn["message"].(string), "another product's DNS proxy is enabled") {
		t.Errorf("warning = %v", warn)
	}
}

// Without an enabled DNS proxy there is only the context line, and a
// disabled proxy does not count.
func TestExemptionContextQuietWithoutDNSProxy(t *testing.T) {
	stubHostContextReads(t, []string{
		"dns_proxy:com.example.old:com.example.old.dnsproxy:disabled",
		"vpn:com.cisco.anyconnect.macos.acsock:com.cisco.anyconnect.macos.acsockext:enabled",
	})
	events := captureExemptionContextLog(t)
	if len(events) != 1 {
		t.Fatalf("got %d events, want the context only: %v", len(events), events)
	}
	if got, ok := events[0]["dns_proxies_enabled"]; ok && got != nil {
		if l, _ := got.([]any); len(l) != 0 {
			t.Errorf("dns_proxies_enabled = %v, want empty", got)
		}
	}
}

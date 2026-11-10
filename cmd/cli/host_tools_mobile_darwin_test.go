package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gitlab.int.windscribe.com/controld/clients/ctrld.git"
	"gitlab.int.windscribe.com/controld/clients/ctrld.git/internal/firewall"
	"gitlab.int.windscribe.com/controld/clients/ctrld.git/internal/mobile"
)

func TestMobileStartsNoHostTools(t *testing.T) {
	marker := fakeHostTools(t)
	stubIOS(t)
	iface := &net.Interface{Name: "en0"}

	_, _ = patchNetIfaceName(iface)
	_, _ = networksetupOutput("-listallhardwareports")
	_ = setDNS(iface, []string{"192.0.2.1"})
	_ = resetDNS(iface)
	_, _ = currentStaticDNS(iface)
	_, _ = runSCUtilDNS()
	osVersion()
	startupMetadata(context.Background())
	if _, err := runNativeTargetCommand(context.Background(), "", "/usr/sbin/scutil"); !errors.Is(err, errNoHostTools) {
		t.Errorf("runNativeTargetCommand error = %v, want %v", err, errNoHostTools)
	}
	if out, code := readHostContext(time.Second, "/usr/sbin/scutil", "--nc", "list"); out != "" || code == "ok" {
		t.Errorf("readHostContext = %q, %q, want no output", out, code)
	}

	requireNoHostTools(t, marker)
}

// The iOS seam alone must turn on every mobile guard of ctrld, because that
// is the only value that is true in a real iOS app.
func TestIOSSeamTurnsOnMobile(t *testing.T) {
	oldIsIOS := mobile.IsIOS
	mobile.IsIOS = func() bool { return true }
	t.Cleanup(func() { mobile.IsIOS = oldIsIOS })
	if !isMobile() {
		t.Error("isMobile() = false with the iOS seam on")
	}
}

// A resolver configuration can turn on firewall mode, which enforces with pf
// on macOS. On iOS the sandbox does not let ctrld start pfctl.
func TestMobileFirewallStartsNoPfctl(t *testing.T) {
	marker := fakeHostTools(t)
	stubIOS(t)
	oldIntercept := dnsIntercept
	t.Cleanup(func() { dnsIntercept = oldIntercept })
	dnsIntercept = true
	p := &prog{cfg: &ctrld.Config{}, allowList: firewall.New(), dnsInterceptState: &pfState{}}
	p.logger.Store(mainLog.Load())

	p.initPlatformFirewall()
	p.firewallFlushPlatform()
	// An error here makes the destination sync warn and retry every few
	// minutes, for enforcement that iOS can never have.
	destinations := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := p.firewallApplyExceptionsPlatform(destinations, nil); err != nil {
		t.Errorf("firewallApplyExceptionsPlatform() = %v, want nil on iOS", err)
	}
	if err := p.firewallReplaceExceptionsPlatform(destinations); err != nil {
		t.Errorf("firewallReplaceExceptionsPlatform() = %v, want nil on iOS", err)
	}
	// The anchor rebuild of the shutdown writes a system file, so the test
	// stops before it. The flushes before it are the reads that matter.
	p.dnsInterceptState = nil
	p.shutdownPlatformFirewall()

	if p.platformFirewallState != nil {
		t.Errorf("platform firewall state = %v, want none on iOS", p.platformFirewallState)
	}
	requireNoHostTools(t, marker)
}

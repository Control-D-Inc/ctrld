package cli

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld/internal/mobile"
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

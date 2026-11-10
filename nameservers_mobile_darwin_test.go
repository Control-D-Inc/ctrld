package ctrld

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cuonglm/osinfo"
)

// fakeHostTools puts fakes of the system tools that ctrld can start on macOS
// first in PATH. Each one writes a marker file, so a test can find a tool
// that ctrld started.
func fakeHostTools(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "started")
	for _, tool := range []string{"scutil", "ipconfig", "networksetup", "stat", "dscl", "system_profiler", "route"} {
		script := "#!/bin/sh\necho " + tool + " >> " + marker + "\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

func stubIOS(t *testing.T) {
	t.Helper()
	old := isIOS
	isIOS = func() bool { return true }
	t.Cleanup(func() { isIOS = old })
}

func TestMobileStartsNoHostTools(t *testing.T) {
	marker := fakeHostTools(t)
	stubIOS(t)
	stubOSInfo(t)
	ctx := context.Background()

	getDNSFromScutil(ctx)
	getAllDHCPNameservers(ctx)
	_, _ = DHCPNameserversForInterface("en0")
	_, _ = patchNetIfaceName(&net.Interface{Name: "en0"})
	ValidInterfaces(ctx)
	DiscoverVPNDNS(ctx)
	getScutilConsoleUser(ctx)
	getConsoleUser(ctx)
	getLowestRegularUser(ctx)
	OSVersion()
	newDohOsHeaderValue()
	SystemMetadataStartup(ctx)
	SystemMetadata(ctx)
	if _, err := DHCPNameserversForInterfaceContext(ctx, "en0"); !errors.Is(err, errNoHostTools) {
		t.Errorf("DHCPNameserversForInterfaceContext error = %v, want %v", err, errNoHostTools)
	}

	if started, err := os.ReadFile(marker); err == nil {
		t.Fatalf("ctrld started system tools on mobile:\n%s", started)
	}
}

// stubOSInfo makes the test fail when ctrld reads the OS version with
// sw_vers. sw_vers has an absolute path, so a fake in PATH cannot catch it.
func stubOSInfo(t *testing.T) {
	t.Helper()
	old := osinfoNew
	osinfoNew = func() *osinfo.OSInfo {
		t.Error("ctrld started sw_vers on mobile")
		return old()
	}
	t.Cleanup(func() { osinfoNew = old })
}

func TestMobileMetadataHasNoHostValues(t *testing.T) {
	stubIOS(t)
	stubOSInfo(t)
	oldSession := discoverSessionUserFn
	discoverSessionUserFn = func(context.Context) string { return "session-user" }
	t.Cleanup(func() { discoverSessionUserFn = oldSession })

	m := SystemMetadataStartup(context.Background())
	if got, want := m[metadataOsKey], OSVersion(); got != want {
		t.Errorf("os = %q, want %q", got, want)
	}
	if !strings.HasPrefix(m[metadataOsKey], runtime.GOOS+" ") {
		t.Errorf("os = %q, want the %s prefix", m[metadataOsKey], runtime.GOOS)
	}
	if user, ok := m[metadataUsernameKey]; ok {
		t.Errorf("mobile metadata sent username %q", user)
	}
	if got := SystemMetadata(context.Background())[metadataUsernameKey]; got != "" {
		t.Errorf("mobile provisioning metadata sent username %q", got)
	}
}

// The DoH OS header is built when the package loads, before any run. On
// iOS it must take the OS version without sw_vers.
func TestMobileDohOsHeaderHasTheVersion(t *testing.T) {
	stubIOS(t)
	stubOSInfo(t)
	header := newDohOsHeaderValue()
	if strings.HasSuffix(header, "-") || strings.HasSuffix(header, osinfo.UnknownRelease) {
		t.Errorf("DoH OS header = %q, want the OS version at the end", header)
	}
}

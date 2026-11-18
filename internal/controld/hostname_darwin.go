package controld

import (
	"os"
	"os/exec"
	"strings"

	"github.com/Control-D-Inc/ctrld/internal/mobile"
)

// isIOS reports whether ctrld runs in an iOS app, where the sandbox does not
// let it start scutil. Tests replace it.
var isIOS = func() bool { return mobile.IsIOS() }

// preferredHostname returns the best available hostname on macOS.
// It prefers scutil --get ComputerName which is the user-configured name
// from System Settings → General → About → Name. This is immune to
// DHCP/network state that can cause os.Hostname() and even LocalHostName
// to return generic names like "Mac.lan" on Sequoia with Private Wi-Fi
// Address enabled.
//
// Fallback chain: ComputerName → LocalHostName → os.Hostname()
func preferredHostname() (string, error) {
	if isIOS() {
		return os.Hostname()
	}
	for _, key := range []string{"ComputerName", "LocalHostName"} {
		if out, err := exec.Command("scutil", "--get", key).Output(); err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				return name, nil
			}
		}
	}
	return os.Hostname()
}

// hostnameHints returns all available hostname sources on macOS for
// diagnostic/fallback purposes. The API can use these to pick the
// best hostname if the primary one looks generic (e.g., "Mac").
func hostnameHints() map[string]string {
	hints := make(map[string]string)
	for _, key := range scutilHostnameKeys() {
		if out, err := exec.Command("scutil", "--get", key).Output(); err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				hints[key] = name
			}
		}
	}
	if h, err := os.Hostname(); err == nil {
		hints["os.Hostname"] = h
	}
	return hints
}

// scutilHostnameKeys lists the scutil keys that hostnameHints reads.
func scutilHostnameKeys() []string {
	if isIOS() {
		return nil
	}
	return []string{"ComputerName", "LocalHostName", "HostName"}
}

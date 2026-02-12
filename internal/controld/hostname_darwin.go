package controld

import (
	"os"
	"os/exec"
	"strings"
)

// preferredHostname returns the best available hostname on macOS.
// It prefers scutil --get ComputerName which is the user-configured name
// from System Settings → General → About → Name. This is immune to
// DHCP/network state that can cause os.Hostname() and even LocalHostName
// to return generic names like "Mac.lan" on Sequoia with Private Wi-Fi
// Address enabled.
//
// Fallback chain: ComputerName → LocalHostName → os.Hostname()
func preferredHostname() (string, error) {
	for _, key := range []string{"ComputerName", "LocalHostName"} {
		if out, err := exec.Command("scutil", "--get", key).Output(); err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				return name, nil
			}
		}
	}
	return os.Hostname()
}

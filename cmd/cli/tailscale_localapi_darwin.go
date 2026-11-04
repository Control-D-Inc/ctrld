//go:build darwin

package cli

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Locations used by the three macOS Tailscale variants. These match
// tailscale.com/safesocket and tailscale.com/paths.
const (
	tailscaleMacsysDir   = "/Library/Tailscale"
	tailscaledUnixSocket = "/var/run/tailscaled.socket"
)

// tailscaleCodeRequirement accepts only the Mac App Store Tailscale network
// extension. Apple re-signs App Store code with its own leaf certificate
// (marker OID 1.2.840.113635.100.6.1.9) and signs a bundle identifier only for
// the developer that owns it; other builds carry Tailscale's team identifier
// W5364U7YZB, which Tailscale publishes for its macOS extension policy.
const tailscaleCodeRequirement = `anchor apple generic and identifier "io.tailscale.ipn.macos.network-extension" and ` +
	`(certificate leaf[field.1.2.840.113635.100.6.1.9] or certificate leaf[subject.OU] = "W5364U7YZB")`

// discoverTailscaleRoutesFn reads Tailscale DNS routes; tests replace it.
//
// discoverTailscaleRoutes reads Tailscale's DNS routes through its LocalAPI.
// ctrld runs as root, so it can read the credentials of each variant. The
// root-owned credentials come first: the Standalone system extension
// (/Library/Tailscale) and open source tailscaled (unix socket). The Mac App
// Store extension (sameuserproof file found with lsof) comes last, and only
// after its process passes a Tailscale code signature check, because any
// local user can start a process with that name.
var discoverTailscaleRoutesFn = discoverTailscaleRoutes

// listAppStoreProofsFn lists the open files of IPNExtension processes; tests
// replace it. "+c 0" prints the full command name, so the parser can require
// an exact match; -c alone matches any command that starts with the name.
var listAppStoreProofsFn = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "lsof", "-n", "-a", "+c", "0", "-c", tailscaleAppStoreProc, "-F", "pcn").Output()
}

// verifyTailscaleProcessFn checks the code signature of a running process;
// tests replace it.
var verifyTailscaleProcessFn = verifyTailscaleProcess

func discoverTailscaleRoutes(ctx context.Context) ([]tailscaleRoute, error) {
	return discoverTailscaleRoutesFrom(ctx, tailscaleLocalAPIEndpoints(ctx))
}

func tailscaleLocalAPIEndpoints(ctx context.Context) []tailscaleLocalAPIEndpoint {
	var eps []tailscaleLocalAPIEndpoint

	if portStr, err := os.Readlink(filepath.Join(tailscaleMacsysDir, "ipnport")); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
			if b, err := os.ReadFile(filepath.Join(tailscaleMacsysDir, "sameuserproof-"+portStr)); err == nil {
				if token := strings.TrimSpace(string(b)); token != "" {
					eps = append(eps, tailscaleLocalAPIEndpoint{name: "standalone", dial: tcpLocalAPIDialer(port), token: token})
				}
			}
		}
	}

	if fi, err := os.Stat(tailscaledUnixSocket); err == nil && fi.Mode()&os.ModeSocket != 0 {
		eps = append(eps, tailscaleLocalAPIEndpoint{
			name: "tailscaled",
			dial: func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", tailscaledUnixSocket)
			},
		})
	}

	return append(eps, appStoreLocalAPIEndpoints(ctx)...)
}

// appStoreLocalAPIEndpoints returns the App Store LocalAPI endpoint of the
// first IPNExtension process that is signed by Tailscale.
func appStoreLocalAPIEndpoints(ctx context.Context) []tailscaleLocalAPIEndpoint {
	out, err := listAppStoreProofsFn(ctx)
	if err != nil {
		return nil
	}
	verified := make(map[int]bool)
	for _, proof := range parseMacOSSameUserProofs(out) {
		ok, seen := verified[proof.pid]
		if !seen {
			ok = verifyTailscaleProcessFn(ctx, proof.pid)
			verified[proof.pid] = ok
		}
		if ok {
			return []tailscaleLocalAPIEndpoint{{name: "app-store", dial: tcpLocalAPIDialer(proof.port), token: proof.token}}
		}
	}
	return nil
}

// verifyTailscaleProcess reports whether the running process pid is signed by
// Tailscale. codesign validates a running process dynamically when given a
// pid instead of a path.
func verifyTailscaleProcess(ctx context.Context, pid int) bool {
	return exec.CommandContext(ctx, "codesign", "--verify", "-R="+tailscaleCodeRequirement, strconv.Itoa(pid)).Run() == nil
}

func tcpLocalAPIDialer(port int) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
}

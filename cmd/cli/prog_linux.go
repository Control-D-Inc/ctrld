package cli

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/kardianos/service"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"

	"github.com/Control-D-Inc/ctrld/internal/dns"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

func init() {
	if r, err := dns.NewOSConfigurator(func(format string, args ...any) {}, &health.Tracker{}, &controlknobs.Knobs{}, "lo"); err == nil {
		useSystemdResolved = r.Mode() == "systemd-resolved"
	}
	// Disable quic-go's ECN support by default, see https://github.com/quic-go/quic-go/issues/3911
	if os.Getenv("QUIC_GO_DISABLE_ECN") == "" {
		os.Setenv("QUIC_GO_DISABLE_ECN", "true")
	}
}

func setDependencies(svc *service.Config) {
	svc.Dependencies = []string{
		"Wants=network-online.target",
		"After=network-online.target",
		"Wants=NetworkManager-wait-online.service",
		"After=NetworkManager-wait-online.service",
		"Wants=nss-lookup.target",
		"After=nss-lookup.target",
	}
	if out, _ := exec.Command("networkctl", "--no-pager").CombinedOutput(); len(out) > 0 {
		if wantsSystemDNetworkdWaitOnline(bytes.NewReader(out)) {
			svc.Dependencies = append(svc.Dependencies, "Wants=systemd-networkd-wait-online.service")
		}
	}
	if routerDeps := router.ServiceDependencies(); len(routerDeps) > 0 {
		svc.Dependencies = append(svc.Dependencies, routerDeps...)
	}
}

func setWorkingDirectory(svc *service.Config, dir string) {
	svc.WorkingDirectory = dir
}

// wantsSystemDNetworkdWaitOnline reports whether "systemd-networkd-wait-online" service
// is required to be added to ctrld dependencies services.
// The input reader r is the output of "networkctl --no-pager" command.
func wantsSystemDNetworkdWaitOnline(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
	// Skip header
	scanner.Scan()
	configured := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[len(fields)-1] == "configured" {
			configured = true
			break
		}
	}
	return configured
}

//go:build darwin

package cli

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

// interceptDNSTargetStateFile persists which service/value ctrld set, so a
// daemon restart (crash, upgrade, plain restart) does not orphan the entry:
// without it a restarted daemon would not know the entry is ctrld's own and
// could neither remove it on shutdown nor keep its bookkeeping consistent.
const interceptDNSTargetStateFile = ".intercept_dns_target"

var (
	interceptDNSTargetStatePathFn          = interceptDNSTargetStatePath
	interceptDefaultRouteInterfaceFn       = netmon.DefaultRouteInterface
	interceptInterfaceByNameFn             = net.InterfaceByName
	interceptPatchNetIfaceNameFn           = patchNetIfaceName
	interceptCurrentStaticDNSFn            = currentStaticDNS
	interceptSaveCurrentStaticDNSFn        = saveCurrentStaticDNS
	interceptSetDNSFn                      = setDNS
	interceptSavedStaticNameserversFn      = ctrld.SavedStaticNameservers
	interceptResetDNSIgnoreUnusableIfaceFn = resetDnsIgnoreUnusableInterface
	interceptDHCPNameserversForInterfaceFn = ctrld.DHCPNameserversForInterface
)

func interceptDNSTargetStatePath() string {
	dir, err := userHomeDir()
	if err != nil {
		return interceptDNSTargetStateFile
	}
	return filepath.Join(dir, interceptDNSTargetStateFile)
}

type interceptDNSTargetState struct {
	Service string `json:"service"`
	Value   string `json:"value"`
}

// loadInterceptDNSTargetStateLocked hydrates in-memory tracking from the
// state file once (only when memory is empty). Callers must hold
// interceptDNSTargetMu.
func (p *prog) loadInterceptDNSTargetStateLocked() {
	if p.interceptDNSTargetService != "" || p.interceptDNSTargetLoaded {
		return
	}
	p.interceptDNSTargetLoaded = true
	data, err := os.ReadFile(interceptDNSTargetStatePathFn())
	if err != nil {
		return
	}
	var st interceptDNSTargetState
	if err := json.Unmarshal(data, &st); err != nil || st.Service == "" || st.Value == "" {
		return
	}
	p.interceptDNSTargetService = st.Service
	p.interceptDNSTargetSetValue = st.Value
	mainLog.Load().Debug().Msgf("intercept DNS target: restored tracking of %s on %q from previous run", st.Value, st.Service)
}

// persistInterceptDNSTargetStateLocked writes (or clears) the state file to
// match in-memory tracking. Callers must hold interceptDNSTargetMu.
func (p *prog) persistInterceptDNSTargetStateLocked() {
	file := interceptDNSTargetStatePathFn()
	if p.interceptDNSTargetService == "" {
		_ = os.Remove(file)
		return
	}
	data, err := json.Marshal(interceptDNSTargetState{Service: p.interceptDNSTargetService, Value: p.interceptDNSTargetSetValue})
	if err != nil {
		return
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		mainLog.Load().Debug().Err(err).Msg("intercept DNS target: could not persist state file")
	}
}

// ensureInterceptDNSTarget guarantees macOS always has an emittable DNS
// target while DNS intercept mode is active.
//
// Intercept mode deliberately never manages interface DNS: pf redirects DNS
// packets in flight. But pf can only redirect packets macOS actually sends,
// and mDNSResponder emits none when the active network service has no DNS
// configured. IPv6-only networks (e.g. iPhone tethering with 464XLAT) supply
// no IPv4 DNS, and the pf ruleset blocks all outbound IPv6 port 53, so such
// networks otherwise end in a total DNS outage with a healthy upstream
// (issue #533).
//
// Only when the default-route service has no usable IPv4 DNS at all does
// ctrld set a loopback DNS value on it — chosen by interceptDNSTargetValue to
// respect the configured listener: the listener IP directly when it serves
// port 53, else a distinct loopback address so the pf lo0 rdr rule rewrites
// to the listener's real port. The entry is removed when the network regains
// IPv4 DNS and on intercept shutdown. Networks that provide IPv4 DNS are
// never modified.
//
// Callers pass a non-nil raw system discovery result to prove discovery ran;
// an empty slice is a valid DNS-less result. The decision itself uses static
// DNS plus DHCP option 6 from the default-route interface, so resolvers on a
// second physical interface cannot suppress the target. Invoked during
// startup, debounced network recovery, and periodic pf watchdog reconciliation.
func (p *prog) ensureInterceptDNSTarget(systemDiscovery []string) {
	if !dnsIntercept || p.dnsInterceptState == nil {
		return
	}
	if systemDiscovery == nil {
		mainLog.Load().Debug().Msg("intercept DNS target: system DNS discovery was not performed; not changing DNS")
		return
	}
	p.interceptDNSTargetMu.Lock()
	defer p.interceptDNSTargetMu.Unlock()
	p.loadInterceptDNSTargetStateLocked()

	drIfaceName, err := interceptDefaultRouteInterfaceFn()
	if err != nil || drIfaceName == "" {
		// Mid-transition with no default route; the next recovery decides.
		return
	}
	iface, err := interceptInterfaceByNameFn(drIfaceName)
	if err != nil || iface == nil {
		return
	}
	// Resolve the network service name (e.g. en5 -> "iPhone USB") so
	// networksetup operates on the right service.
	if _, err := interceptPatchNetIfaceNameFn(iface); err != nil {
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not resolve network service for %s", drIfaceName)
		return
	}

	staticDNS, err := interceptCurrentStaticDNSFn(iface)
	if err != nil {
		// Interfaces without a network service (utun/VPN tunnels) land here:
		// networksetup cannot address them, ctrld never writes to them, and
		// any target set on the underlying physical service stays in place —
		// still correct while ctrld runs.
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not read static DNS for %q", iface.Name)
		return
	}
	// Never count ctrld's own previously-set entry as network-provided DNS,
	// or the next recovery on the same DNS-less network would remove it and
	// the one after re-add it.
	if p.interceptDNSTargetService == iface.Name {
		staticDNS = filterOwnTarget(staticDNS, p.interceptDNSTargetSetValue)
	}
	if hasIPv4DNS(staticDNS) {
		p.removeInterceptDNSTargetLocked("network has usable static IPv4 DNS")
		return
	}

	routeDHCPDNS, err := interceptDHCPNameserversForInterfaceFn(drIfaceName)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not read DHCP DNS for default-route service %q", iface.Name)
		return
	}
	if hasIPv4DNS(routeDHCPDNS) {
		// The default-route service regained DHCP option 6. Remove a target
		// previously set on this or another service.
		p.removeInterceptDNSTargetLocked("network has usable DHCP IPv4 DNS")
		return
	}

	target := p.interceptDNSTargetValue()
	if p.interceptDNSTargetService == iface.Name && p.interceptDNSTargetSetValue == target {
		return // already set on this service
	}
	// Default route moved to a different DNS-less service (or the listener
	// config changed): clear the stale entry first.
	p.removeInterceptDNSTargetLocked("default route service changed")

	// Preserve any existing (IPv6-only) static entries for later restore.
	// saveCurrentStaticDNS filters loopback on write, and
	// savedStaticNameservers filters loopback on read, so ctrld's own
	// loopback target can never be recorded or restored as user DNS.
	if err := interceptSaveCurrentStaticDNSFn(iface); err != nil {
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not save static DNS for %q", iface.Name)
	}
	if err := interceptSetDNSFn(iface, []string{target}); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("intercept DNS target: could not set %s on %q", target, iface.Name)
		return
	}
	p.interceptDNSTargetService = iface.Name
	p.interceptDNSTargetSetValue = target
	p.persistInterceptDNSTargetStateLocked()
	mainLog.Load().Warn().Msgf("intercept DNS target: service %q provides no usable IPv4 DNS; set %s so macOS can emit DNS queries (removed automatically when the network provides IPv4 DNS)", iface.Name, target)
}

// removeInterceptDNSTarget removes a previously set intercept DNS target,
// restoring the service's saved static DNS (or empty). Safe no-op when no
// target was set.
func (p *prog) removeInterceptDNSTarget(reason string) {
	p.interceptDNSTargetMu.Lock()
	defer p.interceptDNSTargetMu.Unlock()
	p.loadInterceptDNSTargetStateLocked()
	p.removeInterceptDNSTargetLocked(reason)
}

// removeInterceptDNSTargetLocked is removeInterceptDNSTarget without locking;
// callers must hold interceptDNSTargetMu.
func (p *prog) removeInterceptDNSTargetLocked(reason string) {
	svc := p.interceptDNSTargetService
	val := p.interceptDNSTargetSetValue
	if svc == "" {
		return
	}
	iface := &net.Interface{Name: svc}
	// Only remove what ctrld set. If the service's DNS changed externally,
	// leave that value alone and discard our stale ownership record.
	cur, err := interceptCurrentStaticDNSFn(iface)
	if err != nil {
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not read %q DNS; retaining cleanup state (%s)", svc, reason)
		return
	}
	if !isInterceptDNSTargetOnly(cur, val) {
		mainLog.Load().Debug().Msgf("intercept DNS target: %q DNS changed externally; not removing (%s)", svc, reason)
		p.clearInterceptDNSTargetStateLocked()
		return
	}
	if saved := interceptSavedStaticNameserversFn(iface); len(saved) > 0 {
		if err := interceptSetDNSFn(iface, saved); err != nil {
			mainLog.Load().Warn().Err(err).Msgf("intercept DNS target: could not restore saved DNS on %q; retaining cleanup state", svc)
			return
		}
	} else if err := interceptResetDNSIgnoreUnusableIfaceFn(iface); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("intercept DNS target: could not reset DNS on %q; retaining cleanup state", svc)
		return
	}
	p.clearInterceptDNSTargetStateLocked()
	mainLog.Load().Info().Msgf("intercept DNS target: removed %s from %q (%s)", val, svc, reason)
}

func (p *prog) clearInterceptDNSTargetStateLocked() {
	p.interceptDNSTargetService = ""
	p.interceptDNSTargetSetValue = ""
	p.persistInterceptDNSTargetStateLocked()
}

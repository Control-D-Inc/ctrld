//go:build darwin

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

// interceptDNSTargetStateFile persists which service/value ctrld set, so a
// daemon restart (crash, upgrade, plain restart) does not orphan the entry:
// without it a restarted daemon would not know the entry is ctrld's own and
// could neither remove it on shutdown nor keep its bookkeeping consistent.
const interceptDNSTargetStateFile = ".intercept_dns_target"

var (
	interceptDNSTargetStatePathFn       = interceptDNSTargetStatePath
	interceptDefaultRouteInterfaceFn    = netmon.DefaultRouteInterface
	interceptInterfaceByNameFn          = net.InterfaceByName
	interceptPatchNetIfaceNameFn        = patchNetIfaceName
	interceptCurrentStaticDNSFn         = readTargetStaticDNS
	interceptNativeCLATDefaultServiceFn = nativeCLATDefaultService
	interceptNativeStaticDNSFn          = readNativeTargetStaticDNS
	interceptSaveStaticDNSSnapshotFn    = func(iface *net.Interface, dns []string, owned string) error {
		return saveTargetStaticDNSSnapshot(ctrld.SavedStaticDnsSettingsFilePath(iface), dns, owned)
	}
	interceptSaveCurrentStaticDNSFn        = saveCurrentStaticDNS
	interceptSetDNSFn                      = setDNS
	interceptSavedStaticNameserversFn      = ctrld.SavedStaticNameservers
	interceptResetDNSIgnoreUnusableIfaceFn = resetDnsIgnoreUnusableInterface
	interceptDHCPNameserversForInterfaceFn = readTargetDHCPNameservers
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
	p.setInterceptDNSTargetLocked(st.Service, st.Value)
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
	p.interceptDNSTargetMu.Lock()
	defer p.interceptDNSTargetMu.Unlock()
	p.loadInterceptDNSTargetStateLocked()
	var diagnostic *dnsTargetDecisionDiagnostic
	if state, ok := p.dnsInterceptState.(*pfState); ok {
		diagnostic = &state.targetDiagnostic
	}
	decision := dnsTargetDecisionContext{
		ownership:    p.interceptDNSTargetOwnershipLocked(),
		generation:   p.recoveryGen.Load(),
		transitionID: p.networkAcceptedGen.Load(),
	}
	// Only completed discovery resolves an outstanding diagnostic. A resolution
	// describes the decision and observed ownership, not successful DNS repair.
	resolvedReason := ""
	defer func() {
		if resolvedReason != "" {
			diagnostic.resolved(decision, p.interceptDNSTargetOwnershipLocked(), resolvedReason)
		}
	}()
	if systemDiscovery == nil {
		diagnostic.failed(decision, "system_discovery", nil)
		mainLog.Load().Debug().Msg("intercept DNS target: system DNS discovery was not performed; not changing DNS")
		return
	}

	drIfaceName, err := interceptDefaultRouteInterfaceFn()
	decision.iface = drIfaceName
	if err != nil || drIfaceName == "" {
		// Mid-transition with no default route; the next recovery decides.
		diagnostic.failed(decision, "default_route", err)
		return
	}
	iface, err := interceptInterfaceByNameFn(drIfaceName)
	if err != nil || iface == nil {
		diagnostic.failed(decision, "interface_lookup", err)
		return
	}
	routeDHCPDNS, dhcpErr := interceptDHCPNameserversForInterfaceFn(drIfaceName)
	nativeFallback := false
	ctx, cancel := context.WithTimeout(context.Background(), nativeTargetReadBudget)
	defer cancel()
	var nativeService nativeTargetService
	readStatic := interceptCurrentStaticDNSFn
	if dhcpErr != nil {
		// Resolve the exact primary UUID before any expanded mutation. A
		// device can have multiple services; the first listed is not proof.
		var nativeErr error
		nativeService, nativeErr = interceptNativeCLATDefaultServiceFn(ctx, drIfaceName)
		nativeFallback = nativeErr == nil && nativeService.ID != "" && nativeService.Name != "" && nativeService.Device == drIfaceName && !hasIPv4DNS(routeDHCPDNS)
		mainLog.Load().Debug().Err(nativeErr).Bool("native_clat_verified", nativeFallback).
			Str("interface", drIfaceName).Msg("intercept DNS target: native fallback evidence")
	}
	if nativeFallback {
		iface.Name = nativeService.Name
		readStatic = func(iface *net.Interface) ([]string, error) { return interceptNativeStaticDNSFn(ctx, iface) }
	} else if _, err := interceptPatchNetIfaceNameFn(iface); err != nil {
		diagnostic.failed(decision, "service_lookup", err)
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not resolve network service for %s", drIfaceName)
		return
	}
	decision.service = iface.Name

	staticDNS, err := readStatic(iface)
	if err != nil {
		diagnostic.failed(decision, "static_dns", err)
		mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not read static DNS for %q", iface.Name)
		return
	}
	// Retain the exact validated snapshot for backup and equality checks,
	// including an owned non-loopback value that must never be snapshotted.
	snapshot := staticDNS
	if nativeFallback {
		device, routeErr := interceptDefaultRouteInterfaceFn()
		check, serviceErr := interceptNativeCLATDefaultServiceFn(ctx, drIfaceName)
		if routeErr != nil || serviceErr != nil || device != drIfaceName || check != nativeService {
			diagnostic.failed(decision, "native_recheck", errors.Join(routeErr, serviceErr))
			return
		}
		current, readErr := readStatic(iface)
		if readErr != nil || ctx.Err() != nil || !slices.Equal(current, snapshot) {
			diagnostic.failed(decision, "static_recheck", errors.Join(readErr, ctx.Err()))
			return
		}
	}
	// Never count ctrld's own previously-set entry as network-provided DNS,
	// or the next recovery on the same DNS-less network would remove it and
	// the one after re-add it.
	if p.interceptDNSTargetService == iface.Name {
		staticDNS = filterOwnTarget(staticDNS, p.interceptDNSTargetSetValue)
	}
	if hasIPv4DNS(staticDNS) {
		resolvedReason = "static_ipv4_dns"
		p.removeInterceptDNSTargetLocked("network has usable static IPv4 DNS")
		return
	}
	if nativeFallback && slices.ContainsFunc(staticDNS, func(s string) bool {
		ip := net.ParseIP(s)
		return ip != nil && ip.To4() == nil && ip.IsLoopback()
	}) {
		// lo0 can serve another local resolver. The static backup reader
		// discards loopback, so expanded admission cannot safely replace it.
		resolvedReason = "static_loopback_dns"
		return
	}

	if dhcpErr != nil && !nativeFallback {
		diagnostic.failed(decision, "dhcp_dns", dhcpErr)
		mainLog.Load().Debug().Err(dhcpErr).Msgf("intercept DNS target: could not read DHCP DNS for default-route service %q", iface.Name)
		return
	}
	if hasIPv4DNS(routeDHCPDNS) {
		resolvedReason = "dhcp_ipv4_dns"
		// The default-route service regained DHCP option 6. Remove a target
		// previously set on this or another service.
		p.removeInterceptDNSTargetLocked("network has usable DHCP IPv4 DNS")
		return
	}

	resolvedReason = "dns_less_network"
	target := p.interceptDNSTargetValue()
	if p.interceptDNSTargetService == iface.Name && p.interceptDNSTargetSetValue == target {
		return // already set on this service
	}
	if nativeFallback {
		owned := ""
		if p.interceptDNSTargetService == iface.Name {
			owned = p.interceptDNSTargetSetValue
		}
		if err := interceptSaveStaticDNSSnapshotFn(iface, snapshot, owned); err != nil {
			return // no expanded mutation without a restorable backup
		}
	}
	// Default route moved to a different DNS-less service (or the listener
	// config changed): clear the stale entry first.
	p.removeInterceptDNSTargetLocked("default route service changed")
	if p.interceptDNSTargetService != "" {
		return // cleanup failed; never overwrite ownership of the old service
	}

	// Preserve any existing (IPv6-only) static entries for later restore.
	// saveCurrentStaticDNS filters loopback on write, and
	// savedStaticNameservers filters loopback on read, so ctrld's own
	// loopback target can never be recorded or restored as user DNS.
	if !nativeFallback {
		if err := interceptSaveCurrentStaticDNSFn(iface); err != nil {
			mainLog.Load().Debug().Err(err).Msgf("intercept DNS target: could not save static DNS for %q", iface.Name)
		}
	}
	if err := interceptSetDNSFn(iface, []string{target}); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("intercept DNS target: could not set %s on %q", target, iface.Name)
		return
	}
	p.setInterceptDNSTargetLocked(iface.Name, target)
	p.persistInterceptDNSTargetStateLocked()
	journal(mainLog.Load().Warn()).Str("service", iface.Name).Str("target", target).
		Bool("native_clat_fallback", nativeFallback).
		Str("reason", "dns_less_network").
		Msgf("intercept DNS target: service %q provides no usable IPv4 DNS; set %s so macOS can emit DNS queries (removed automatically when the network provides IPv4 DNS)", iface.Name, target)
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
		p.clearInterceptDNSTargetStateLocked()
		// ctrld owns the DNS of the service no longer, and a later outage
		// report needs the moment that ownership ended.
		journal(mainLog.Load().Info()).Str("service", svc).Str("target", val).
			Str("reason", "external_change").
			Msgf("intercept DNS target: %q DNS changed externally; not removing (%s)", svc, reason)
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
	journal(mainLog.Load().Info()).Str("service", svc).Str("target", val).Str("reason", reason).
		Msgf("intercept DNS target: removed %s from %q (%s)", val, svc, reason)
}

func (p *prog) interceptDNSTargetOwnershipLocked() dnsTargetOwnership {
	return dnsTargetOwnership{p.interceptDNSTargetService, p.interceptDNSTargetSetValue}
}

func (p *prog) clearInterceptDNSTargetStateLocked() {
	p.setInterceptDNSTargetLocked("", "")
	p.persistInterceptDNSTargetStateLocked()
}

// setInterceptDNSTargetLocked stores the service that ctrld owns and the value
// it wrote, and publishes the value for the readers that take no lock. Callers
// must hold interceptDNSTargetMu.
func (p *prog) setInterceptDNSTargetLocked(service, value string) {
	p.interceptDNSTargetService = service
	p.interceptDNSTargetSetValue = value
	p.publishInterceptTarget(value)
}

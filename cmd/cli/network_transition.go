package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
	ctrldnet "github.com/Control-D-Inc/ctrld/internal/net"
)

type networkChangeMonitor interface {
	RegisterChangeCallback(netmon.ChangeFunc) func()
	IsMajorChangeFrom(*netmon.State, *netmon.State) bool
	Start()
}

// Tests replace these functions to avoid changes to host DNS and PF state.
var (
	newNetworkChangeMonitorFn = func(logf func(string, ...any)) (networkChangeMonitor, error) {
		return netmon.New(logf)
	}
	networkChangeCurrentStateFn = func(delta *netmon.ChangeDelta) *netmon.State {
		if delta.Monitor != nil {
			return delta.Monitor.InterfaceState()
		}
		return delta.New
	}
	readNetworkSourceStateFn        = readNetworkSourceState
	networkChangeValidInterfacesFn  = ctrld.ValidInterfaces
	networkChangeDefaultRouteIPFn   = (*prog).defaultRouteIP
	networkChangeReconcileFn        = (*prog).reconcileNetworkChange
	networkChangeIgnoredInterceptFn = (*prog).handleDNSInterceptIgnoredNetworkChange
	handleRecoveryForTransitionFn   = (*prog).handleRecoveryForTransition
	recoveryResetDNSFn              = (*prog).resetDNS
)

// Minor callbacks have no observation sequence in netmon v1.74.0. Read only
// current interface addresses and flags rather than trusting their arrival order.
func readNetworkSourceState() (*netmon.State, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	state := &netmon.State{Interface: map[string]netmon.Interface{}, InterfaceIPs: map[string][]netip.Prefix{}}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		state.Interface[iface.Name] = netmon.Interface{Interface: &iface}
		for _, address := range addresses {
			var ip net.IP
			switch address := address.(type) {
			case *net.IPNet:
				ip = address.IP
			case *net.IPAddr:
				ip = address.IP
			default:
				return nil, errors.New("unsupported interface address type")
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				return nil, errors.New("invalid interface address")
			}
			addr = addr.Unmap()
			state.InterfaceIPs[iface.Name] = append(state.InterfaceIPs[iface.Name], netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return state, nil
}

// netmon v1.74.0 caches only major snapshots. Minor and time-jump events
// belong to their Old snapshot, not their distinct New snapshot.
func networkSnapshotCurrent(delta *netmon.ChangeDelta, major bool, current *netmon.State) bool {
	if major || delta.Monitor == nil {
		return current == delta.New
	}
	return current == delta.Old
}

// Callers hold networkSourceMu. Preserve minor changes within the current
// major epoch, but use a new major snapshot even before its callback runs.
func (p *prog) sourceCommitState(delta *netmon.ChangeDelta) *netmon.State {
	if delta.Monitor != nil {
		if current := networkChangeCurrentStateFn(delta); current != p.networkSourceEpoch {
			return current
		}
	}
	return p.networkSourceState
}

// sourceInvalidReason considers all up interfaces, not just hardware ports: a
// preferred source remains valid if it moved to another active interface.
func sourceInvalidReason(state *netmon.State, ip net.IP) string {
	if ip == nil || state == nil {
		return ""
	}
	reason := "address_removed"
	for name, prefixes := range state.InterfaceIPs {
		for _, prefix := range prefixes {
			if !ip.Equal(net.ParseIP(prefix.Addr().String())) {
				continue
			}
			iface, exists := state.Interface[name]
			if exists && iface.IsUp() {
				return ""
			}
			if exists {
				reason = "interface_down"
			} else if reason != "interface_down" {
				reason = "interface_removed"
			}
		}
	}
	return reason
}

func validateDefaultLocalIPsFromDelta(ctx context.Context, state *netmon.State, transitionID uint64) {
	before4, before6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	reason4, reason6 := sourceInvalidReason(state, before4), sourceInvalidReason(state, before6)
	if reason4 != "" {
		ctrld.SetDefaultLocalIPv4(ctx, nil)
	}
	if reason6 != "" {
		ctrld.SetDefaultLocalIPv6(ctx, nil)
	}
	if reason4 == "" && reason6 == "" {
		return
	}
	// One warning per actual invalidation, not per notification or query. The
	// normal warning buffer retains this summary when debug traffic rotates.
	ctrld.LoggerFromCtx(ctx).Warn().Uint64("transition_id", transitionID).
		Str("default_route", state.DefaultRouteInterface).
		Str("source_ipv4_before", before4.String()).Str("source_ipv6_before", before6.String()).
		Str("source_ipv4_after", ctrld.GetDefaultLocalIPv4().String()).
		Str("source_ipv6_after", ctrld.GetDefaultLocalIPv6().String()).
		Str("ipv4_clear_reason", reason4).Str("ipv6_clear_reason", reason6).
		Msg("Removed stale resolver source")
}

type recoveryDiagnostic struct {
	logger       *ctrld.Logger
	transitionID uint64
	generation   uint64
	reason       RecoveryReason
	started      time.Time
	firstFailure sync.Once
	failed       atomic.Bool
}

func recoveryReasonName(reason RecoveryReason) string {
	switch reason {
	case RecoveryReasonNetworkChange:
		return "network_change"
	case RecoveryReasonRegularFailure:
		return "upstream_failure"
	case RecoveryReasonOSFailure:
		return "os_resolver_failure"
	default:
		return "unknown"
	}
}

func (d *recoveryDiagnostic) event(e *ctrld.LogEvent) *ctrld.LogEvent {
	return e.Uint64("transition_id", d.transitionID).Uint64("recovery_generation", d.generation).
		Str("recovery_reason", recoveryReasonName(d.reason))
}

func (d *recoveryDiagnostic) failure(err error) {
	d.firstFailure.Do(func() {
		d.failed.Store(true)
		// Classify only; resolver errors can contain queried names or endpoints.
		failure := "upstream_error"
		var networkError net.Error
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			failure = "source_unavailable"
		} else if ctrldnet.IsUnreachable(err) {
			failure = "network_unreachable"
		} else if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
			failure = "timeout"
		}
		d.event(d.log().Warn()).Str("failure", failure).
			Msg("Recovery waiting for upstream; first failure")
	})
}

func (d *recoveryDiagnostic) end(outcome string) {
	e := d.log().Debug()
	if outcome == "canceled" || d.failed.Load() {
		e = d.log().Warn()
	}
	d.event(e).Str("outcome", outcome).Bool("had_failure", d.failed.Load()).Int64("duration_ms", time.Since(d.started).Milliseconds()).Msg("Recovery end")
}

func (d *recoveryDiagnostic) log() *ctrld.Logger {
	if d.logger != nil {
		return d.logger
	}
	return mainLog.Load()
}

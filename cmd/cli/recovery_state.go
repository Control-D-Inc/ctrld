package cli

import "context"

// beginRecovery atomically transfers ownership of shared recovery state. A
// network change cancels and replaces the current owner without exposing a nil
// recoveryCancel gap; other triggers are coalesced while an owner exists.
func (p *prog) beginRecovery(reason RecoveryReason) (ctx context.Context, gen uint64, intercept bool, ok bool) {
	p.recoveryCancelMu.Lock()
	defer p.recoveryCancelMu.Unlock()

	if reason != RecoveryReasonNetworkChange && p.recoveryCancel != nil {
		return nil, 0, false, false
	}
	if p.recoveryCancel != nil {
		p.recoveryCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	gen = p.recoveryGen.Add(1)
	intercept = dnsIntercept && p.dnsInterceptState != nil
	p.recoveryCancel = cancel
	p.recoveryRunning.Store(true)
	p.recoveryBypass.Store(intercept)
	return ctx, gen, intercept, true
}

func (p *prog) recoveryOwnsState(gen uint64) bool {
	p.recoveryCancelMu.Lock()
	defer p.recoveryCancelMu.Unlock()
	return p.recoveryGen.Load() == gen && p.recoveryCancel != nil
}

func systemNameserversForInterceptRetry() []string {
	_, system := initializeOsResolverWithSystemNameserversFn(true)
	if system == nil {
		return []string{}
	}
	return system
}

// completeRecovery releases shared state only if gen still owns it. The bypass
// reset is unconditional because live intercept state can disappear while a
// recovery is running, but a stale true flag still affects proxy routing.
func (p *prog) completeRecovery(gen uint64) bool {
	p.recoveryCancelMu.Lock()
	defer p.recoveryCancelMu.Unlock()
	if p.recoveryGen.Load() != gen || p.recoveryCancel == nil {
		return false
	}
	p.recoveryBypass.Store(false)
	p.recoveryRunning.Store(false)
	p.recoveryCancel = nil
	return true
}

// recoveryCanceledCleanup resets shared recovery state after a canceled or
// failed recovery, but only when the recovery identified by gen was NOT
// superseded by a newer one (issue #597).
//
// A network-change cancellation is normally followed immediately by a new
// handleRecovery that owns recoveryBypass/recoveryRunning/recoveryCancel;
// clearing them here would disable the successor's bypass mid-flight and
// make it uncancellable. But when the canceled recovery is the LAST one
// (e.g. the tail of a network flap burst), nothing else will ever clear the
// flags: the daemon would stay in recovery bypass forever — every query
// detouring to the OS resolver — and the DNS-settings watchdog would stay
// permanently disabled.
func (p *prog) recoveryCanceledCleanup(gen uint64) {
	if !p.completeRecovery(gen) {
		// Superseded: the newer recovery owns the shared state.
		return
	}
	mainLog.Load().Info().Msg("Recovery canceled with no successor; cleared recovery state and DHCP bypass")
}

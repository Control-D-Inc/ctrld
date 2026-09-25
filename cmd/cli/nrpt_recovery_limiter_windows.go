//go:build windows

package cli

import (
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

const (
	// Default to current behavior: keep recovering indefinitely unless configured.
	defaultNRPTRecoveryMaxAttempts = 0
	defaultNRPTRecoveryCooldown    = 30 * time.Minute

	// Require more than one good health tick before clearing the circuit. A probe can
	// pass briefly after delete/re-add even when another agent recreates broken NRPT state.
	nrptRecoveryStableSuccessesToReset = 2
)

type nrptRecoveryLimiter struct {
	mu              sync.Mutex
	attempts        int
	stableSuccesses int
	cooldownUntil   time.Time
	lastSkipLog     time.Time
}

func nrptRecoveryMaxAttempts(cfg *ctrld.Config) int {
	if cfg != nil && cfg.Service.NRPTRecoveryMaxAttempts != nil {
		return *cfg.Service.NRPTRecoveryMaxAttempts
	}
	return defaultNRPTRecoveryMaxAttempts
}

func nrptRecoveryCooldown(cfg *ctrld.Config) time.Duration {
	if cfg != nil && cfg.Service.NRPTRecoveryCooldown != nil {
		return *cfg.Service.NRPTRecoveryCooldown
	}
	return defaultNRPTRecoveryCooldown
}

func (l *nrptRecoveryLimiter) allow(now time.Time, cfg *ctrld.Config) (bool, time.Duration) {
	maxAttempts := nrptRecoveryMaxAttempts(cfg)
	if maxAttempts <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Before(l.cooldownUntil) {
		return false, l.cooldownUntil.Sub(now)
	}
	return true, 0
}

func (l *nrptRecoveryLimiter) recordRecoveryFlow(now time.Time, cfg *ctrld.Config) {
	maxAttempts := nrptRecoveryMaxAttempts(cfg)
	if maxAttempts <= 0 {
		return
	}

	cooldown := nrptRecoveryCooldown(cfg)
	if cooldown <= 0 {
		cooldown = defaultNRPTRecoveryCooldown
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.stableSuccesses = 0
	l.attempts++
	if l.attempts >= maxAttempts {
		l.cooldownUntil = now.Add(cooldown)
	}
}

func (l *nrptRecoveryLimiter) recordStableSuccess() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.stableSuccesses++
	if l.stableSuccesses >= nrptRecoveryStableSuccessesToReset {
		l.attempts = 0
		l.cooldownUntil = time.Time{}
		l.lastSkipLog = time.Time{}
	}
}

func (l *nrptRecoveryLimiter) shouldLogSkip(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastSkipLog.IsZero() || now.Sub(l.lastSkipLog) >= 5*time.Minute {
		l.lastSkipLog = now
		return true
	}
	return false
}

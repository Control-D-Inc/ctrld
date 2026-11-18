//go:build windows

package cli

import (
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

func TestNRPTRecoveryLimiterCooldownAndStableReset(t *testing.T) {
	maxAttempts := 2
	cooldown := 10 * time.Minute
	cfg := &ctrld.Config{}
	cfg.Service.NRPTRecoveryMaxAttempts = &maxAttempts
	cfg.Service.NRPTRecoveryCooldown = &cooldown

	limiter := &nrptRecoveryLimiter{}
	now := time.Unix(100, 0)

	if ok, wait := limiter.allow(now, cfg); !ok || wait != 0 {
		t.Fatalf("initial allow = %v, %v; want true, 0", ok, wait)
	}

	limiter.recordRecoveryFlow(now, cfg)
	if ok, wait := limiter.allow(now.Add(time.Second), cfg); !ok || wait != 0 {
		t.Fatalf("allow after first flow = %v, %v; want true, 0", ok, wait)
	}

	limiter.recordRecoveryFlow(now.Add(2*time.Second), cfg)
	if ok, wait := limiter.allow(now.Add(3*time.Second), cfg); ok || wait <= 0 {
		t.Fatalf("allow after max flows = %v, %v; want false, positive wait", ok, wait)
	}

	limiter.recordStableSuccess()
	if ok, _ := limiter.allow(now.Add(4*time.Second), cfg); ok {
		t.Fatal("one stable success cleared cooldown; want cooldown to remain")
	}

	limiter.recordStableSuccess()
	if ok, wait := limiter.allow(now.Add(5*time.Second), cfg); !ok || wait != 0 {
		t.Fatalf("allow after stable reset = %v, %v; want true, 0", ok, wait)
	}
}

func TestNRPTRecoveryLimiterDefaultIsUnlimited(t *testing.T) {
	cfg := &ctrld.Config{}
	limiter := &nrptRecoveryLimiter{}
	now := time.Unix(100, 0)

	for i := 0; i < 10; i++ {
		limiter.recordRecoveryFlow(now.Add(time.Duration(i)*time.Second), cfg)
	}
	if ok, wait := limiter.allow(now.Add(time.Hour), cfg); !ok || wait != 0 {
		t.Fatalf("default allow after recovery flows = %v, %v; want true, 0", ok, wait)
	}
}

func TestNRPTRecoveryLimiterUnlimited(t *testing.T) {
	maxAttempts := 0
	cfg := &ctrld.Config{}
	cfg.Service.NRPTRecoveryMaxAttempts = &maxAttempts

	limiter := &nrptRecoveryLimiter{}
	now := time.Unix(100, 0)

	for i := 0; i < 10; i++ {
		limiter.recordRecoveryFlow(now.Add(time.Duration(i)*time.Second), cfg)
	}
	if ok, wait := limiter.allow(now.Add(time.Hour), cfg); !ok || wait != 0 {
		t.Fatalf("unlimited allow = %v, %v; want true, 0", ok, wait)
	}
}

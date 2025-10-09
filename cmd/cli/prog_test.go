package cli

import (
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/stretchr/testify/assert"
)

func Test_prog_dnsWatchdogEnabled(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}}

	// Default value is true.
	assert.True(t, p.dnsWatchdogEnabled())

	tests := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p.cfg.Service.DnsWatchdogEnabled = &tc.enabled
			assert.Equal(t, tc.enabled, p.dnsWatchdogEnabled())
		})
	}
}

func Test_prog_dnsWatchdogInterval(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}}

	// Default value is 20s.
	assert.Equal(t, dnsWatchdogDefaultInterval, p.dnsWatchdogDuration())

	tests := []struct {
		name     string
		duration time.Duration
		expected time.Duration
	}{
		{"valid", time.Minute, time.Minute},
		{"zero", 0, dnsWatchdogDefaultInterval},
		{"nagative", time.Duration(-1 * time.Minute), dnsWatchdogDefaultInterval},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p.cfg.Service.DnsWatchdogInvterval = &tc.duration
			assert.Equal(t, tc.expected, p.dnsWatchdogDuration())
		})
	}
}

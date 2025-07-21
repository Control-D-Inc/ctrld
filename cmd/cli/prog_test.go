package cli

import (
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/Control-D-Inc/ctrld"
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

func Test_shouldUpgrade(t *testing.T) {
	// Helper function to create a version
	makeVersion := func(v string) *semver.Version {
		ver, err := semver.NewVersion(v)
		if err != nil {
			t.Fatalf("failed to create version %s: %v", v, err)
		}
		return ver
	}

	tests := []struct {
		name           string
		versionTarget  string
		currentVersion *semver.Version
		shouldUpgrade  bool
		description    string
	}{
		{
			name:           "empty version target",
			versionTarget:  "",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should skip upgrade when version target is empty",
		},
		{
			name:           "invalid version target",
			versionTarget:  "invalid-version",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should skip upgrade when version target is invalid",
		},
		{
			name:           "same version",
			versionTarget:  "v1.0.0",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should skip upgrade when target version equals current version",
		},
		{
			name:           "older version",
			versionTarget:  "v1.0.0",
			currentVersion: makeVersion("v1.1.0"),
			shouldUpgrade:  false,
			description:    "should skip upgrade when target version is older than current version",
		},
		{
			name:           "patch upgrade allowed",
			versionTarget:  "v1.0.1",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  true,
			description:    "should allow patch version upgrade within same major version",
		},
		{
			name:           "minor upgrade allowed",
			versionTarget:  "v1.1.0",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  true,
			description:    "should allow minor version upgrade within same major version",
		},
		{
			name:           "major upgrade blocked",
			versionTarget:  "v2.0.0",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should block major version upgrade",
		},
		{
			name:           "major downgrade blocked",
			versionTarget:  "v1.0.0",
			currentVersion: makeVersion("v2.0.0"),
			shouldUpgrade:  false,
			description:    "should block major version downgrade",
		},
		{
			name:           "version without v prefix",
			versionTarget:  "1.0.1",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  true,
			description:    "should handle version target without v prefix",
		},
		{
			name:           "complex version upgrade allowed",
			versionTarget:  "v1.5.3",
			currentVersion: makeVersion("v1.4.2"),
			shouldUpgrade:  true,
			description:    "should allow complex version upgrade within same major version",
		},
		{
			name:           "complex major upgrade blocked",
			versionTarget:  "v3.1.0",
			currentVersion: makeVersion("v2.5.3"),
			shouldUpgrade:  false,
			description:    "should block complex major version upgrade",
		},
		{
			name:           "pre-release version upgrade allowed",
			versionTarget:  "v1.0.1-beta.1",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  true,
			description:    "should allow pre-release version upgrade within same major version",
		},
		{
			name:           "pre-release major upgrade blocked",
			versionTarget:  "v2.0.0-alpha.1",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should block pre-release major version upgrade",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create test logger
			testLogger := &ctrld.Logger{Logger: zap.NewNop()}

			// Call the function and capture the result
			result := shouldUpgrade(tc.versionTarget, tc.currentVersion, testLogger)

			// Assert the expected result
			assert.Equal(t, tc.shouldUpgrade, result, tc.description)
		})
	}
}

func Test_selfUpgradeCheck(t *testing.T) {
	// Helper function to create a version
	makeVersion := func(v string) *semver.Version {
		ver, err := semver.NewVersion(v)
		if err != nil {
			t.Fatalf("failed to create version %s: %v", v, err)
		}
		return ver
	}

	tests := []struct {
		name           string
		versionTarget  string
		currentVersion *semver.Version
		shouldUpgrade  bool
		description    string
	}{
		{
			name:           "upgrade allowed",
			versionTarget:  "v1.0.1",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  true,
			description:    "should allow upgrade and attempt to perform it",
		},
		{
			name:           "upgrade blocked",
			versionTarget:  "v2.0.0",
			currentVersion: makeVersion("v1.0.0"),
			shouldUpgrade:  false,
			description:    "should block upgrade and not attempt to perform it",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create test logger
			testLogger := &ctrld.Logger{Logger: zap.NewNop()}

			// Call the function and capture the result
			result := selfUpgradeCheck(tc.versionTarget, tc.currentVersion, testLogger)

			// Assert the expected result
			assert.Equal(t, tc.shouldUpgrade, result, tc.description)
		})
	}
}

func Test_performUpgrade(t *testing.T) {
	tests := []struct {
		name           string
		versionTarget  string
		expectedResult bool
		description    string
	}{
		{
			name:           "valid version target",
			versionTarget:  "v1.0.1",
			expectedResult: true,
			description:    "should attempt to perform upgrade with valid version target",
		},
		{
			name:           "empty version target",
			versionTarget:  "",
			expectedResult: true,
			description:    "should attempt to perform upgrade even with empty version target",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create test logger
			testLogger := &ctrld.Logger{Logger: zap.NewNop()}
			// Call the function and capture the result
			result := performUpgrade(tc.versionTarget, testLogger)
			assert.Equal(t, tc.expectedResult, result, tc.description)
		})
	}
}

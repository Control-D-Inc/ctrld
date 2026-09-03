package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// captureMainLog swaps mainLog for a test-local buffer logger and restores
// the previous logger on cleanup. Asserting on the shared logOutput sink is
// order-dependent: a test that ran earlier can re-store mainLog (Windows'
// Test_validInterfaces calls initConsoleLogging), leaving the shared buffer
// stale for every later test.
func captureMainLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.AddSync(buf),
		zap.DebugLevel,
	)
	old := mainLog.Load()
	mainLog.Store(&ctrld.Logger{Logger: zap.New(core)})
	t.Cleanup(func() { mainLog.Store(old) })
	return buf
}

func TestProvisionTokenShapeValid(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"too short", "abcde", false},
		{"minimum length", "abcdef", true},
		{"maximum length", strings.Repeat("a", 64), true},
		{"too long", strings.Repeat("a", 65), false},
		{"contains space", "org-v1- abc", false},
		{"contains tab", "org-v1-\tabc", false},
		{"contains newline", "org-v1-\nabc", false},
		{"contains control char", "org-v1-\x00abc", false},
		{"sane with prefix", "org-v1-abcdef123456", true},
		{"sane without prefix", "legacytoken123", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := provisionTokenShapeValid(tc.token); got != tc.want {
				t.Errorf("provisionTokenShapeValid(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// TestCdUIDFromProvTokenMalformedToken proves a malformed --cd-org value is
// classified before any network attempt: no call reaches fetchResolverUIDFn,
// and the malformed value itself never appears in the persisted message.
func TestCdUIDFromProvTokenMalformedToken(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldFetch, oldHostname := fetchResolverUIDFn, customHostname
	t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })

	cdUID = ""
	const malformed = "ab cd"
	cdOrg = malformed
	customHostname = ""

	called := false
	fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
		called = true
		return nil, nil
	}

	if got := cdUIDFromProvToken(); got != "" {
		t.Errorf("cdUIDFromProvToken() = %q, want empty on failure", got)
	}
	if called {
		t.Error("fetchResolverUIDFn was called; malformed token must be rejected before any network attempt")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeProvisionTokenMalformed] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeProvisionTokenMalformed])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeProvisionTokenMalformed) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeProvisionTokenMalformed)
	}
	if r.Stage != string(provisionStageInput) {
		t.Errorf("stage = %q, want %q", r.Stage, provisionStageInput)
	}
	if strings.Contains(r.Message, malformed) {
		t.Errorf("malformed token leaked into result message: %q", r.Message)
	}
}

// TestCdUIDFromProvTokenPrefixlessTokenProceeds proves a token missing the
// "org-v1-" prefix is not rejected - only warned about - since legacy codes
// may lack it.
func TestCdUIDFromProvTokenPrefixlessTokenProceeds(t *testing.T) {
	_, _ = stubProvisionGlobals(t)
	logBuf := captureMainLog(t)
	oldFetch, oldHostname := fetchResolverUIDFn, customHostname
	t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })

	cdUID = ""
	cdOrg = "legacytoken123"
	customHostname = ""

	called := false
	fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
		called = true
		return &controld.ResolverConfig{UID: "resolved-uid"}, nil
	}

	if got := cdUIDFromProvToken(); got != "resolved-uid" {
		t.Errorf("cdUIDFromProvToken() = %q, want resolved-uid", got)
	}
	if !called {
		t.Error("fetchResolverUIDFn was not called; a prefixless-but-sane token must still proceed")
	}
	if !strings.Contains(logBuf.String(), "org-v1-") {
		t.Error("expected a warning mentioning the org-v1- prefix")
	}
}

// TestCdUIDFromProvTokenInvalidCustomHostname proves an invalid
// --custom-hostname value is classified before any network attempt, with a
// message that names the field and format, and never leaks the provision
// token.
func TestCdUIDFromProvTokenInvalidCustomHostname(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldFetch, oldHostname := fetchResolverUIDFn, customHostname
	t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })

	cdUID = ""
	const secretToken = "org-v1-secret-token-42"
	cdOrg = secretToken
	customHostname = "foo@bar"

	called := false
	fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
		called = true
		return nil, nil
	}

	if got := cdUIDFromProvToken(); got != "" {
		t.Errorf("cdUIDFromProvToken() = %q, want empty on failure", got)
	}
	if called {
		t.Error("fetchResolverUIDFn was called; invalid custom hostname must be rejected before any network attempt")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeCustomHostnameInvalid] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeCustomHostnameInvalid])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeCustomHostnameInvalid) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeCustomHostnameInvalid)
	}
	if !strings.Contains(r.Message, "allowed format") {
		t.Errorf("message = %q, want it to contain the allowed format", r.Message)
	}
	if strings.Contains(r.Message, secretToken) {
		t.Errorf("provision token leaked into result message: %q", r.Message)
	}
}

// TestCdUIDFromProvTokenFoldableHostnameLogsNotice proves a hostname that
// ctrld accepts, but ControlD's device-name formatting would fold or strip,
// gets a notice - not a failure - and provisioning still proceeds.
func TestCdUIDFromProvTokenFoldableHostnameLogsNotice(t *testing.T) {
	_, _ = stubProvisionGlobals(t)
	logBuf := captureMainLog(t)
	oldFetch, oldHostname := fetchResolverUIDFn, customHostname
	t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })

	cdUID = ""
	cdOrg = "org-v1-abcdef123456"
	customHostname = "foo.bar"

	fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
		return &controld.ResolverConfig{UID: "resolved-uid"}, nil
	}

	if got := cdUIDFromProvToken(); got != "resolved-uid" {
		t.Errorf("cdUIDFromProvToken() = %q, want resolved-uid", got)
	}
	if !strings.Contains(logBuf.String(), "foo.bar") {
		t.Error("expected a notice naming the foldable hostname")
	}
}

func TestValidateInterceptModeFlag(t *testing.T) {
	oldMode := interceptMode
	t.Cleanup(func() { interceptMode = oldMode })

	t.Run("valid values proceed", func(t *testing.T) {
		exitCode, _ := stubProvisionGlobals(t)
		for _, mode := range []string{"", "off", "dns", "hard"} {
			interceptMode = mode
			if !validateInterceptModeFlag(mode) {
				t.Errorf("validateInterceptModeFlag(%q) = false, want true", mode)
			}
			if *exitCode != -1 {
				t.Errorf("mode %q: provisionExit called with %d, want no exit", mode, *exitCode)
			}
		}
	})

	t.Run("invalid value is classified", func(t *testing.T) {
		exitCode, _ := stubProvisionGlobals(t)
		interceptMode = "fds"
		if validateInterceptModeFlag("fds") {
			t.Error("validateInterceptModeFlag(\"fds\") = true, want false")
		}
		if *exitCode != provisionExitCodeForCode[provisionCodeInterceptModeInvalid] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeInterceptModeInvalid])
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatalf("no provision result written: %v", err)
		}
		if r.Code != string(provisionCodeInterceptModeInvalid) {
			t.Errorf("code = %q, want %q", r.Code, provisionCodeInterceptModeInvalid)
		}
		for _, want := range []string{"off", "dns", "hard"} {
			if !strings.Contains(r.Message, want) {
				t.Errorf("message = %q, want it to contain %q", r.Message, want)
			}
		}
	})
}

// TestCheckStrFlagEmptyClassifiesEmptyCdOrg proves an explicit empty --cd-org
// is classified as a malformed provisioning token rather than a bare fatal.
func TestCheckStrFlagEmptyClassifiesEmptyCdOrg(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	cmd := &cobra.Command{}
	cmd.Flags().String(cdOrgFlagName, "", "")
	if err := cmd.Flags().Set(cdOrgFlagName, ""); err != nil {
		t.Fatal(err)
	}

	if checkStrFlagEmpty(cmd, cdOrgFlagName) {
		t.Error("checkStrFlagEmpty() = true, want false for an explicit empty --cd-org")
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeProvisionTokenMalformed] {
		t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeProvisionTokenMalformed])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeProvisionTokenMalformed) {
		t.Errorf("code = %q, want %q", r.Code, provisionCodeProvisionTokenMalformed)
	}
	if r.Stage != string(provisionStageInput) {
		t.Errorf("stage = %q, want %q", r.Stage, provisionStageInput)
	}
	if !strings.Contains(r.Message, cdOrgFlagName) {
		t.Errorf("message = %q, want it to name --%s", r.Message, cdOrgFlagName)
	}
}

// TestCheckStrFlagEmptyProceedsWhenNotChangedOrNotEmpty proves the two cases
// that must not classify: the flag was never set, and it was set to a
// non-empty value.
func TestCheckStrFlagEmptyProceedsWhenNotChangedOrNotEmpty(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)

	t.Run("flag never set", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String(cdOrgFlagName, "", "")
		if !checkStrFlagEmpty(cmd, cdOrgFlagName) {
			t.Error("checkStrFlagEmpty() = false, want true when the flag was never set")
		}
	})

	t.Run("flag set to a non-empty value", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String(cdOrgFlagName, "", "")
		if err := cmd.Flags().Set(cdOrgFlagName, "org-v1-abc"); err != nil {
			t.Fatal(err)
		}
		if !checkStrFlagEmpty(cmd, cdOrgFlagName) {
			t.Error("checkStrFlagEmpty() = false, want true for a non-empty value")
		}
	})

	if *exitCode != -1 {
		t.Errorf("provisionExit called with %d, want no exit", *exitCode)
	}
}

// TestValidateCdAndNextDNSFlagsClassifiesConflict proves --cd or --cd-org
// combined with --nextdns is classified as INVALID_FLAG_COMBINATION, naming
// every flag involved.
func TestValidateCdAndNextDNSFlagsClassifiesConflict(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldCdUID, oldCdOrg, oldNextdns := cdUID, cdOrg, nextdns
	t.Cleanup(func() { cdUID, cdOrg, nextdns = oldCdUID, oldCdOrg, oldNextdns })

	t.Run("non-conflicting combinations proceed", func(t *testing.T) {
		cases := []struct{ cdUID, cdOrg, nextdns string }{
			{"", "", ""},
			{"uid123", "", ""},
			{"", "org-v1-abc", ""},
			{"", "", "nextdns-id"},
		}
		for _, tc := range cases {
			cdUID, cdOrg, nextdns = tc.cdUID, tc.cdOrg, tc.nextdns
			if !validateCdAndNextDNSFlags() {
				t.Errorf("validateCdAndNextDNSFlags() = false for cdUID=%q cdOrg=%q nextdns=%q, want true", tc.cdUID, tc.cdOrg, tc.nextdns)
			}
		}
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want no exit", *exitCode)
		}
	})

	t.Run("cd-org with nextdns is classified", func(t *testing.T) {
		cdUID, cdOrg, nextdns = "", "org-v1-abc", "nextdns-id"
		if validateCdAndNextDNSFlags() {
			t.Error("validateCdAndNextDNSFlags() = true, want false")
		}
		if *exitCode != provisionExitCodeForCode[provisionCodeInvalidFlagCombination] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeInvalidFlagCombination])
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatalf("no provision result written: %v", err)
		}
		if r.Code != string(provisionCodeInvalidFlagCombination) {
			t.Errorf("code = %q, want %q", r.Code, provisionCodeInvalidFlagCombination)
		}
		if r.Stage != string(provisionStageInput) {
			t.Errorf("stage = %q, want %q", r.Stage, provisionStageInput)
		}
		for _, want := range []string{cdUidFlagName, cdOrgFlagName, nextdnsFlagName} {
			if !strings.Contains(r.Message, want) {
				t.Errorf("message = %q, want it to name --%s", r.Message, want)
			}
		}
	})

	t.Run("cd with nextdns is classified", func(t *testing.T) {
		cdUID, cdOrg, nextdns = "uid123", "", "nextdns-id"
		if validateCdAndNextDNSFlags() {
			t.Error("validateCdAndNextDNSFlags() = true, want false")
		}
		if *exitCode != provisionExitCodeForCode[provisionCodeInvalidFlagCombination] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeInvalidFlagCombination])
		}
	})
}

// TestValidateCdUpstreamProtocol proves an invalid --proto value is
// classified only once --cd is in play, and that notify runs when given.
func TestValidateCdUpstreamProtocol(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldCdUID, oldProto := cdUID, cdUpstreamProto
	t.Cleanup(func() { cdUID, cdUpstreamProto = oldCdUID, oldProto })

	t.Run("no --cd proceeds regardless of protocol", func(t *testing.T) {
		cdUID = ""
		cdUpstreamProto = "garbage"
		if !validateCdUpstreamProtocol(nil) {
			t.Error("validateCdUpstreamProtocol(nil) = false, want true when --cd is not set")
		}
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want no exit", *exitCode)
		}
	})

	t.Run("valid protocols proceed", func(t *testing.T) {
		cdUID = "uid123"
		for _, proto := range []string{ctrld.ResolverTypeDOH, ctrld.ResolverTypeDOH3} {
			cdUpstreamProto = proto
			if !validateCdUpstreamProtocol(nil) {
				t.Errorf("validateCdUpstreamProtocol(nil) = false for proto %q, want true", proto)
			}
		}
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want no exit", *exitCode)
		}
	})

	t.Run("invalid protocol is classified and notifies", func(t *testing.T) {
		cdUID = "uid123"
		cdUpstreamProto = "quic"
		notified := false
		if validateCdUpstreamProtocol(func() { notified = true }) {
			t.Error("validateCdUpstreamProtocol() = true, want false")
		}
		if !notified {
			t.Error("notify not called")
		}
		if *exitCode != provisionExitCodeForCode[provisionCodeInvalidFlagCombination] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeInvalidFlagCombination])
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatalf("no provision result written: %v", err)
		}
		if r.Code != string(provisionCodeInvalidFlagCombination) {
			t.Errorf("code = %q, want %q", r.Code, provisionCodeInvalidFlagCombination)
		}
		if !strings.Contains(r.Message, "quic") || !strings.Contains(r.Message, "doh") {
			t.Errorf("message = %q, want it to name the given and allowed values", r.Message)
		}
	})
}

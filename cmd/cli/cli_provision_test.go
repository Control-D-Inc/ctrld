package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// TestApiFailureCode covers the preflight-error mapping: a deleted device
// gets its own code (it drives self-uninstall), other permanent rejections
// are generic, anything else is retryable reachability trouble.
func TestApiFailureCode(t *testing.T) {
	rejection := func(status, code int) error {
		e := &controld.ErrorResponse{StatusCode: status}
		e.ErrorField.Code = code
		e.ErrorField.Message = "api said no"
		return e
	}

	tests := []struct {
		name     string
		err      error
		wantCode provisionFailureCode
		wantOk   bool
	}{
		{name: "nil error", err: nil, wantCode: "", wantOk: false},
		{
			name:     "deleted device maps to device invalid",
			err:      rejection(http.StatusNotFound, controld.InvalidConfigCode),
			wantCode: provisionCodeAPIDeviceInvalid,
			wantOk:   true,
		},
		{
			name:     "revoked credentials map to rejected",
			err:      rejection(http.StatusUnauthorized, 0),
			wantCode: provisionCodeAPIRejected,
			wantOk:   true,
		},
		{
			name:     "server error maps to unreachable",
			err:      rejection(http.StatusBadGateway, 0),
			wantCode: provisionCodeAPIUnreachable,
			wantOk:   true,
		},
		{
			name:     "network failure maps to unreachable",
			err:      retryableNetworkErr(),
			wantCode: provisionCodeAPIUnreachable,
			wantOk:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := apiFailureCode(tc.err)
			if ok != tc.wantOk {
				t.Fatalf("apiFailureCode() ok = %v, want %v", ok, tc.wantOk)
			}
			if code != tc.wantCode {
				t.Errorf("apiFailureCode() code = %s, want %s", code, tc.wantCode)
			}
		})
	}
}

// TestApiFailureCodeMapsRejectionReason covers the token_* reasons the API sends in
// error.metadata.reason on a provisioning-token rejection. An absent or unknown
// reason must fall back to the generic API_REJECTED exactly as before this reason
// field existed.
func TestApiFailureCodeMapsRejectionReason(t *testing.T) {
	rejectionWithReason := func(reason string) error {
		e := &controld.ErrorResponse{StatusCode: http.StatusBadRequest}
		e.ErrorField.Code = 40003
		e.ErrorField.Message = "invalid token"
		e.ErrorField.Metadata.Reason = reason
		return e
	}

	tests := []struct {
		name     string
		reason   string
		wantCode provisionFailureCode
	}{
		{name: "token_invalid", reason: "token_invalid", wantCode: provisionCodeTokenInvalid},
		{name: "token_expired", reason: "token_expired", wantCode: provisionCodeTokenExpired},
		{name: "token_limit_reached", reason: "token_limit_reached", wantCode: provisionCodeTokenLimitReached},
		{name: "token_disabled", reason: "token_disabled", wantCode: provisionCodeTokenDisabled},
		{name: "reason absent falls back", reason: "", wantCode: provisionCodeAPIRejected},
		{name: "unknown reason falls back", reason: "some_future_reason", wantCode: provisionCodeAPIRejected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := apiFailureCode(rejectionWithReason(tc.reason))
			if !ok {
				t.Fatal("apiFailureCode() ok = false, want true")
			}
			if code != tc.wantCode {
				t.Errorf("apiFailureCode() code = %s, want %s", code, tc.wantCode)
			}
		})
	}
}

// TestApiFailureCodeSurvivesMalformedReasonType covers a rejection body whose
// metadata.reason is the wrong JSON type end to end: decode it exactly as
// internal/controld does (json.Unmarshal into the same exported type), then
// classify it. Before the metadata decode fix, this body failed the whole
// decode and apiFailureCode never saw an *ErrorResponse at all, so it fell
// back to API_UNREACHABLE - the retryable bootstrap code - instead of the
// permanent rejection this HTTP 400 with a known error code actually is.
func TestApiFailureCodeSurvivesMalformedReasonType(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "reason as a number", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":12345}}}`},
		{name: "reason as an object", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":{"inner":"value"}}}}`},
		{name: "reason as null", body: `{"error":{"message":"invalid token","code":40003,"metadata":{"reason":null}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &controld.ErrorResponse{StatusCode: http.StatusBadRequest}
			if err := json.Unmarshal([]byte(tc.body), e); err != nil {
				t.Fatalf("a malformed reason must not fail the whole decode: %v", err)
			}
			code, ok := apiFailureCode(e)
			if !ok {
				t.Fatal("apiFailureCode() ok = false, want true")
			}
			if code != provisionCodeAPIRejected {
				t.Errorf("apiFailureCode() code = %s, want %s (not %s)", code, provisionCodeAPIRejected, provisionCodeAPIUnreachable)
			}
		})
	}
}

// TestCdUIDFromProvTokenReasonCodes covers the full path from an API rejection
// reason to a persisted result file: each known reason gets its own code, exit
// code, and stage, with a message naming the field and a next action but never
// echoing the token. Absent and unknown reasons keep the generic rejection.
func TestCdUIDFromProvTokenReasonCodes(t *testing.T) {
	const secretToken = "org-secret-token-999"

	tests := []struct {
		name         string
		reason       string
		wantCode     provisionFailureCode
		wantContains string
	}{
		{name: "token_invalid", reason: "token_invalid", wantCode: provisionCodeTokenInvalid, wantContains: "provisioning code"},
		{name: "token_expired", reason: "token_expired", wantCode: provisionCodeTokenExpired, wantContains: "expired"},
		{name: "token_limit_reached", reason: "token_limit_reached", wantCode: provisionCodeTokenLimitReached, wantContains: "limit"},
		{name: "token_disabled", reason: "token_disabled", wantCode: provisionCodeTokenDisabled, wantContains: "invalidated"},
		{name: "reason absent", reason: "", wantCode: provisionCodeAPIRejected, wantContains: ""},
		{name: "unknown reason", reason: "brand_new_reason", wantCode: provisionCodeAPIRejected, wantContains: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, _ := stubProvisionGlobals(t)
			oldFetch, oldHostname := fetchResolverUIDFn, customHostname
			t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })
			cdUID = ""
			cdOrg = secretToken
			customHostname = ""

			rejected := &controld.ErrorResponse{StatusCode: http.StatusBadRequest}
			rejected.ErrorField.Code = 40003
			rejected.ErrorField.Message = "invalid token " + secretToken
			rejected.ErrorField.Metadata.Reason = tc.reason
			fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
				return nil, rejected
			}

			if got := cdUIDFromProvToken(); got != "" {
				t.Errorf("cdUIDFromProvToken() = %q, want empty on failure", got)
			}
			if *exitCode != provisionExitCodeForCode[tc.wantCode] {
				t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[tc.wantCode])
			}
			r, err := readProvisionResult()
			if err != nil {
				t.Fatalf("no provision result written: %v", err)
			}
			if r.Code != string(tc.wantCode) {
				t.Errorf("code = %q, want %q", r.Code, tc.wantCode)
			}
			if r.Stage != string(provisionStageBootstrap) {
				t.Errorf("stage = %q, want bootstrap", r.Stage)
			}
			if tc.wantContains != "" && !strings.Contains(r.Message, tc.wantContains) {
				t.Errorf("message = %q, want it to contain %q", r.Message, tc.wantContains)
			}
			if strings.Contains(r.Message, secretToken) {
				t.Errorf("token leaked into result message: %q", r.Message)
			}
		})
	}
}

func stubProvisionGlobals(t *testing.T) (exitCode *int, notified *bool) {
	t.Helper()
	oldCdUID, oldCdOrg := cdUID, cdOrg
	oldExit, oldUninstall := provisionExit, uninstallInvalidCdUIDFn
	t.Cleanup(func() {
		cdUID, cdOrg = oldCdUID, oldCdOrg
		provisionExit, uninstallInvalidCdUIDFn = oldExit, oldUninstall
	})
	overrideProvisionResultPath(t)
	code := -1
	provisionExit = func(c int) { code = c }
	n := false
	return &code, &n
}

func TestHandleAPIPreflightFailure(t *testing.T) {
	deviceInvalid := func() error {
		e := &controld.ErrorResponse{StatusCode: http.StatusNotFound}
		e.ErrorField.Code = controld.InvalidConfigCode
		e.ErrorField.Message = "device does not exist"
		return e
	}
	rejected := func() error {
		e := &controld.ErrorResponse{StatusCode: http.StatusUnauthorized}
		e.ErrorField.Message = "bad token"
		return e
	}

	t.Run("permanent rejection returns cleanly", func(t *testing.T) {
		exitCode, notified := stubProvisionGlobals(t)
		handleAPIPreflightFailure(&prog{}, rejected(), func() { *notified = true })
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want a clean return", *exitCode)
		}
		if !*notified {
			t.Error("notify not called")
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatal(err)
		}
		if r.Code != string(provisionCodeAPIRejected) {
			t.Errorf("code = %q, want API_REJECTED", r.Code)
		}
	})

	t.Run("deleted device self-uninstalls and returns cleanly", func(t *testing.T) {
		exitCode, notified := stubProvisionGlobals(t)
		uninstalled := false
		uninstallInvalidCdUIDFn = func(_ *prog, _ *ctrld.Logger, _ bool) bool {
			uninstalled = true
			return true
		}
		handleAPIPreflightFailure(&prog{}, deviceInvalid(), func() { *notified = true })
		if *exitCode != -1 {
			t.Errorf("provisionExit called with %d, want a clean return", *exitCode)
		}
		if !uninstalled {
			t.Error("self-uninstall not attempted")
		}
		if !*notified {
			t.Error("notify not called")
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatal(err)
		}
		if r.Code != string(provisionCodeAPIDeviceInvalid) {
			t.Errorf("code = %q, want API_DEVICE_INVALID", r.Code)
		}
	})

	t.Run("unreachable exits nonzero", func(t *testing.T) {
		exitCode, notified := stubProvisionGlobals(t)
		handleAPIPreflightFailure(&prog{}, retryableNetworkErr(), func() { *notified = true })
		if *exitCode != provisionExitCodeForCode[provisionCodeAPIUnreachable] {
			t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[provisionCodeAPIUnreachable])
		}
		if !*notified {
			t.Error("notify not called")
		}
		r, err := readProvisionResult()
		if err != nil {
			t.Fatal(err)
		}
		if r.Code != string(provisionCodeAPIUnreachable) {
			t.Errorf("code = %q, want API_UNREACHABLE", r.Code)
		}
	})

	t.Run("bare uid from a composite --cd value is redacted", func(t *testing.T) {
		_, _ = stubProvisionGlobals(t)
		cdUID = "deviceabc/clientxyz"
		cdOrg = ""
		err := fmt.Errorf("failed: api says deviceabc is unknown")
		handleAPIPreflightFailure(&prog{}, err, func() {})
		r, rerr := readProvisionResult()
		if rerr != nil {
			t.Fatal(rerr)
		}
		if strings.Contains(r.Message, "deviceabc") {
			t.Errorf("bare uid leaked into message: %q", r.Message)
		}
	})
}

// TestDoValidateCdRemoteConfigClassifiesAPIFailure covers the direct
// "--cd <uid>" install path (fatal=true): a fetch failure must classify on
// the provisioning boundary with the same per-class codes as the daemon-side
// preflight, instead of a bare fatal.
func TestDoValidateCdRemoteConfigClassifiesAPIFailure(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldFetch := fetchResolverConfig
	t.Cleanup(func() { fetchResolverConfig = oldFetch })

	deviceInvalid := func() error {
		e := &controld.ErrorResponse{StatusCode: http.StatusNotFound}
		e.ErrorField.Code = controld.InvalidConfigCode
		e.ErrorField.Message = "device does not exist"
		return e
	}
	rejected := func() error {
		e := &controld.ErrorResponse{StatusCode: http.StatusUnauthorized}
		e.ErrorField.Message = "bad token"
		return e
	}

	tests := []struct {
		name     string
		err      error
		wantCode provisionFailureCode
	}{
		{name: "device invalid", err: deviceInvalid(), wantCode: provisionCodeAPIDeviceInvalid},
		{name: "permanent rejection", err: rejected(), wantCode: provisionCodeAPIRejected},
		{name: "unreachable", err: retryableNetworkErr(), wantCode: provisionCodeAPIUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
				return nil, tc.err
			}
			if err := doValidateCdRemoteConfig("device-uid-123", true); err == nil {
				t.Error("doValidateCdRemoteConfig() error = nil, want the fetch error back")
			}
			if *exitCode != provisionExitCodeForCode[tc.wantCode] {
				t.Errorf("exit = %d, want %d", *exitCode, provisionExitCodeForCode[tc.wantCode])
			}
			r, err := readProvisionResult()
			if err != nil {
				t.Fatalf("no provision result written: %v", err)
			}
			if r.Code != string(tc.wantCode) {
				t.Errorf("code = %q, want %q", r.Code, tc.wantCode)
			}
		})
	}
}

// TestDoValidateCdRemoteConfigNonFatalReturnsError proves the restart path
// (fatal=false) is unaffected: it still just warns and hands the error back,
// with no process exit and no result file.
func TestDoValidateCdRemoteConfigNonFatalReturnsError(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldFetch := fetchResolverConfig
	t.Cleanup(func() { fetchResolverConfig = oldFetch })

	wantErr := errors.New("network unreachable")
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return nil, wantErr
	}

	if err := doValidateCdRemoteConfig("device-uid-123", false); !errors.Is(err, wantErr) {
		t.Errorf("doValidateCdRemoteConfig() error = %v, want %v", err, wantErr)
	}
	if *exitCode != -1 {
		t.Errorf("provisionExit called with %d, want no exit", *exitCode)
	}
	if _, err := readProvisionResult(); err == nil {
		t.Error("expected no provision result written for the non-fatal path")
	}
}

// TestDoValidateCdRemoteConfigDoesNotSelfUninstall proves the direct-cd
// install path never triggers self-uninstall on a device-invalid failure:
// this runs before the service is installed, so there is nothing to remove.
func TestDoValidateCdRemoteConfigDoesNotSelfUninstall(t *testing.T) {
	_, _ = stubProvisionGlobals(t)
	oldFetch, oldUninstall := fetchResolverConfig, uninstallInvalidCdUIDFn
	t.Cleanup(func() { fetchResolverConfig, uninstallInvalidCdUIDFn = oldFetch, oldUninstall })

	uninstallCalled := false
	uninstallInvalidCdUIDFn = func(*prog, *ctrld.Logger, bool) bool {
		uninstallCalled = true
		return true
	}
	e := &controld.ErrorResponse{StatusCode: http.StatusNotFound}
	e.ErrorField.Code = controld.InvalidConfigCode
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return nil, e
	}

	_ = doValidateCdRemoteConfig("device-uid-123", true)

	if uninstallCalled {
		t.Error("doValidateCdRemoteConfig triggered self-uninstall; nothing is installed yet on this path")
	}
}

func TestCdUIDFromProvTokenFailureEmitsCode(t *testing.T) {
	exitCode, _ := stubProvisionGlobals(t)
	oldFetch, oldHostname := fetchResolverUIDFn, customHostname
	t.Cleanup(func() { fetchResolverUIDFn, customHostname = oldFetch, oldHostname })
	cdUID = ""
	cdOrg = "org-secret-token-123"
	customHostname = ""

	rejected := &controld.ErrorResponse{StatusCode: http.StatusUnauthorized}
	rejected.ErrorField.Message = "bad provision token org-secret-token-123"
	fetchResolverUIDFn = func(context.Context, *controld.UtilityOrgRequest, string, bool) (*controld.ResolverConfig, error) {
		return nil, rejected
	}

	if got := cdUIDFromProvToken(); got != "" {
		t.Errorf("cdUIDFromProvToken() = %q, want empty on failure", got)
	}
	if *exitCode != provisionExitCodeForCode[provisionCodeAPIRejected] {
		t.Errorf("exit = %d, want API_REJECTED exit %d", *exitCode, provisionExitCodeForCode[provisionCodeAPIRejected])
	}
	r, err := readProvisionResult()
	if err != nil {
		t.Fatalf("no provision result written: %v", err)
	}
	if r.Code != string(provisionCodeAPIRejected) {
		t.Errorf("code = %q, want API_REJECTED", r.Code)
	}
	if strings.Contains(r.Message, cdOrg) {
		t.Errorf("token leaked into result message: %q", r.Message)
	}
}

// Regression test: an explicit ip:port that fails to bind used to die with a
// bare fatal log automation could not tell apart from any other crash. It
// must report a stable code through the provisioning result instead.
func TestTryUpdateListenerConfigConfiguredAddrUnavailable(t *testing.T) {
	// Occupy one localhost port on both udp and tcp, and hold both for the
	// whole test so ctrld's own bind attempt is guaranteed to fail.
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a udp port: %v", err)
	}
	defer udpConn.Close()

	host, portStr, err := net.SplitHostPort(udpConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("could not parse reserved address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("could not parse reserved port: %v", err)
	}

	tcpLn, err := net.Listen("tcp", net.JoinHostPort(host, portStr))
	if err != nil {
		t.Fatalf("could not reserve the same port on tcp: %v", err)
	}
	defer tcpLn.Close()

	oldCdUID, oldCdOrg, oldNextdns, oldIntercept := cdUID, cdOrg, nextdns, interceptMode
	oldPath, oldExit := provisionResultPath, provisionExit
	t.Cleanup(func() {
		cdUID, cdOrg, nextdns, interceptMode = oldCdUID, oldCdOrg, oldNextdns, oldIntercept
		provisionResultPath, provisionExit = oldPath, oldExit
	})
	// Non-cd, non-nextdns mode with an explicit ip:port: no fallback checks,
	// the path that used to reach the fatal exit directly.
	cdUID = ""
	cdOrg = ""
	nextdns = ""
	interceptMode = ""

	tmpDir := t.TempDir()
	provisionResultPath = func() string { return filepath.Join(tmpDir, "provision_result.json") }

	var exitCode int
	var exited bool
	provisionExit = func(code int) { exitCode = code; exited = true }

	cfg := &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{
			"0": {IP: host, Port: port},
		},
	}

	notified := false
	_, ok := tryUpdateListenerConfig(cfg, func() { notified = true }, true)

	if ok {
		t.Error("tryUpdateListenerConfig ok = true, want false")
	}
	if !notified {
		t.Error("expected notifyFunc to run before the recorded exit")
	}
	if !exited {
		t.Fatal("expected provisionExit to be called")
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42 (LISTENER_CONFIGURED_ADDR_UNAVAILABLE)", exitCode)
	}

	result, err := readProvisionResult()
	if err != nil {
		t.Fatalf("could not read provision result: %v", err)
	}
	if result.Code != string(provisionCodeListenerAddrUnavail) {
		t.Errorf("result code = %s, want %s", result.Code, provisionCodeListenerAddrUnavail)
	}
	if result.Stage != string(provisionStageListener) {
		t.Errorf("result stage = %s, want %s", result.Stage, provisionStageListener)
	}
	if result.ExitCode != 42 {
		t.Errorf("result exit code = %d, want 42", result.ExitCode)
	}
	if result.Detail == nil || len(result.Detail.Attempts) == 0 {
		t.Fatal("expected the occupied address to appear as a recorded bind attempt")
	}

	occupiedAddr := net.JoinHostPort(host, portStr)
	// Windows words WSAEADDRINUSE differently, so only require the canonical
	// message on platforms that produce it.
	requireInUseText := runtime.GOOS != "windows"
	var sawUDP, sawTCP bool
	for _, a := range result.Detail.Attempts {
		if a.Addr != occupiedAddr || a.OSError == "" {
			continue
		}
		if requireInUseText && !strings.Contains(strings.ToLower(a.OSError), "address already in use") {
			continue
		}
		switch a.Proto {
		case "udp":
			sawUDP = true
		case "tcp":
			sawTCP = true
		}
	}
	if !sawUDP {
		t.Error("expected a udp attempt on the occupied address with a bind error")
	}
	if !sawTCP {
		t.Error("expected a tcp attempt on the occupied address with a bind error")
	}
}

// The exhaustion path (exit 41) is not covered: forcing every fallback,
// including a freshly randomized ip/port, to fail has no deterministic seam,
// so a test would race whatever ports are free on the host.

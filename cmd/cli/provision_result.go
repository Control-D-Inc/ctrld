package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Control-D-Inc/ctrld"
)

// A terminal provisioning failure reports the same stable code on three
// surfaces: a persisted result file, one fixed-format output line, and a
// stage-scoped process exit code. docs/provisioning-failure-codes.md maps
// each code to its scenario and must stay in sync with the constants below.
// Codes are append-only once released; renaming or reusing one breaks the
// support contract.

type provisionStage string

const (
	provisionStageInput     provisionStage = "input"
	provisionStageBootstrap provisionStage = "bootstrap"
	provisionStageListener  provisionStage = "listener"
	provisionStageService   provisionStage = "service"
)

type provisionFailureCode string

const (
	provisionCodeProvisionTokenMalformed provisionFailureCode = "PROVISION_TOKEN_MALFORMED"
	provisionCodeCustomHostnameInvalid   provisionFailureCode = "CUSTOM_HOSTNAME_INVALID"
	provisionCodeInterceptModeInvalid    provisionFailureCode = "INTERCEPT_MODE_INVALID"
	provisionCodeInvalidFlagCombination  provisionFailureCode = "INVALID_FLAG_COMBINATION"
	provisionCodeAPIUnreachable          provisionFailureCode = "API_UNREACHABLE"
	provisionCodeAPIRejected             provisionFailureCode = "API_REJECTED"
	provisionCodeAPIDeviceInvalid        provisionFailureCode = "API_DEVICE_INVALID"
	provisionCodeTokenInvalid            provisionFailureCode = "TOKEN_INVALID"
	provisionCodeTokenExpired            provisionFailureCode = "TOKEN_EXPIRED"
	provisionCodeTokenLimitReached       provisionFailureCode = "TOKEN_LIMIT_REACHED"
	provisionCodeTokenDisabled           provisionFailureCode = "TOKEN_DISABLED"
	provisionCodeListenerBindFailed      provisionFailureCode = "LISTENER_BIND_FAILED"
	provisionCodeListenerAddrUnavail     provisionFailureCode = "LISTENER_CONFIGURED_ADDR_UNAVAILABLE"
	provisionCodeServiceInstall          provisionFailureCode = "SERVICE_INSTALL_FAILED"
	provisionCodeServiceStartFailed      provisionFailureCode = "SERVICE_START_FAILED"
	provisionCodeServiceSelfCheck        provisionFailureCode = "SERVICE_SELFCHECK_FAILED"
	provisionCodeUnclassified            provisionFailureCode = "UNCLASSIFIED"
)

var allProvisionFailureCodes = []provisionFailureCode{
	provisionCodeProvisionTokenMalformed,
	provisionCodeCustomHostnameInvalid,
	provisionCodeInterceptModeInvalid,
	provisionCodeInvalidFlagCombination,
	provisionCodeAPIUnreachable,
	provisionCodeAPIRejected,
	provisionCodeAPIDeviceInvalid,
	provisionCodeTokenInvalid,
	provisionCodeTokenExpired,
	provisionCodeTokenLimitReached,
	provisionCodeTokenDisabled,
	provisionCodeListenerBindFailed,
	provisionCodeListenerAddrUnavail,
	provisionCodeServiceInstall,
	provisionCodeServiceStartFailed,
	provisionCodeServiceSelfCheck,
	provisionCodeUnclassified,
}

var provisionStageForCode = map[provisionFailureCode]provisionStage{
	provisionCodeProvisionTokenMalformed: provisionStageInput,
	provisionCodeCustomHostnameInvalid:   provisionStageInput,
	provisionCodeInterceptModeInvalid:    provisionStageInput,
	provisionCodeInvalidFlagCombination:  provisionStageInput,
	provisionCodeAPIUnreachable:          provisionStageBootstrap,
	provisionCodeAPIRejected:             provisionStageBootstrap,
	provisionCodeAPIDeviceInvalid:        provisionStageBootstrap,
	provisionCodeTokenInvalid:            provisionStageBootstrap,
	provisionCodeTokenExpired:            provisionStageBootstrap,
	provisionCodeTokenLimitReached:       provisionStageBootstrap,
	provisionCodeTokenDisabled:           provisionStageBootstrap,
	provisionCodeListenerBindFailed:      provisionStageListener,
	provisionCodeListenerAddrUnavail:     provisionStageListener,
	provisionCodeServiceInstall:          provisionStageService,
	provisionCodeServiceStartFailed:      provisionStageService,
	provisionCodeServiceSelfCheck:        provisionStageService,
	provisionCodeUnclassified:            provisionStageService,
}

// Exit codes are grouped by stage (input 20-29, bootstrap 30-39, listener
// 40-49, service 50-59) so the exit code alone names the failed stage. 0-3
// belong to "ctrld status" and 126 to the deactivation pin check; never
// reuse those.
var provisionExitCodeForCode = map[provisionFailureCode]int{
	provisionCodeProvisionTokenMalformed: 21,
	provisionCodeCustomHostnameInvalid:   22,
	provisionCodeInterceptModeInvalid:    23,
	provisionCodeInvalidFlagCombination:  24,
	provisionCodeAPIUnreachable:          30,
	provisionCodeAPIRejected:             31,
	provisionCodeAPIDeviceInvalid:        32,
	provisionCodeTokenInvalid:            33,
	provisionCodeTokenExpired:            34,
	provisionCodeTokenLimitReached:       35,
	provisionCodeTokenDisabled:           36,
	provisionCodeListenerBindFailed:      41,
	provisionCodeListenerAddrUnavail:     42,
	provisionCodeServiceInstall:          51,
	provisionCodeServiceStartFailed:      52,
	provisionCodeServiceSelfCheck:        53,
	provisionCodeUnclassified:            59,
}

const (
	provisionResultFileName = "provision_result.json"
	// Detail identifies a failure, it is not a log. Caps keep the artifact
	// small and predictable.
	maxProvisionBindAttempts = 12
	maxProvisionStringLen    = 256
)

type provisionBindAttempt struct {
	Addr    string `json:"addr"`
	Proto   string `json:"proto"`
	OSError string `json:"os_error"`
}

type provisionDetail struct {
	Attempts []provisionBindAttempt `json:"attempts,omitempty"`
}

type provisionResult struct {
	Version   int              `json:"version"`
	Timestamp string           `json:"timestamp"`
	Stage     string           `json:"stage"`
	Code      string           `json:"code"`
	ExitCode  int              `json:"exit_code"`
	Message   string           `json:"message"`
	Detail    *provisionDetail `json:"detail,omitempty"`
}

// provisionResultPath is a var so tests can point it at a temp dir.
var provisionResultPath = func() string {
	return absHomeDir(provisionResultFileName)
}

// provisionExit is a var so tests can observe the exit code instead of dying.
var provisionExit = os.Exit

// newProvisionResult builds a result with every field bounded and the given
// secrets stripped. The artifact reaches installer logs and support tickets,
// so callers pass every secret in scope (provision token, cd UID).
func newProvisionResult(code provisionFailureCode, message string, attempts []provisionBindAttempt, secrets ...string) *provisionResult {
	sanitize := func(s string) string {
		s = redactSecrets(s, secrets...)
		if len(s) > maxProvisionStringLen {
			// Cut on a rune boundary so a localized OS error does not end in
			// a broken multi-byte sequence.
			cut := maxProvisionStringLen
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			s = s[:cut]
		}
		return s
	}
	r := &provisionResult{
		Version:   1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Stage:     string(provisionStageForCode[code]),
		Code:      string(code),
		ExitCode:  provisionExitCodeForCode[code],
		Message:   sanitize(message),
	}
	if len(attempts) > 0 {
		if len(attempts) > maxProvisionBindAttempts {
			attempts = attempts[:maxProvisionBindAttempts]
		}
		detail := &provisionDetail{Attempts: make([]provisionBindAttempt, 0, len(attempts))}
		for _, a := range attempts {
			detail.Attempts = append(detail.Attempts, provisionBindAttempt{
				Addr:    sanitize(a.Addr),
				Proto:   sanitize(a.Proto),
				OSError: sanitize(a.OSError),
			})
		}
		r.Detail = detail
	}
	return r
}

// redactSecrets removes every non-empty secret from s.
func redactSecrets(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return s
}

// provisionResultTrusted rejects a result whose code, stage, or exit code is
// not part of the known contract, so a corrupt or planted file cannot drive
// what "ctrld start" logs and exits with.
func provisionResultTrusted(r *provisionResult) bool {
	code := provisionFailureCode(r.Code)
	stage, ok := provisionStageForCode[code]
	if !ok {
		return false
	}
	return r.Stage == string(stage) && r.ExitCode == provisionExitCodeForCode[code]
}

func (r *provisionResult) failureLine() string {
	return fmt.Sprintf("provisioning failed: stage=%s code=%s (exit %d)", r.Stage, r.Code, r.ExitCode)
}

// writeProvisionResult persists the result atomically (temp file + rename in
// the same directory) so a reader never sees a partial file.
func writeProvisionResult(r *provisionResult) error {
	path := provisionResultPath()
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), provisionResultFileName+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func readProvisionResult() (*provisionResult, error) {
	buf, err := os.ReadFile(provisionResultPath())
	if err != nil {
		return nil, err
	}
	r := &provisionResult{}
	if err := json.Unmarshal(buf, r); err != nil {
		return nil, err
	}
	return r, nil
}

// clearProvisionResult removes a stale result once provisioning succeeds, so
// support never diagnoses a healthy install from an old failure.
func clearProvisionResult() {
	if err := os.Remove(provisionResultPath()); err != nil && !os.IsNotExist(err) {
		mainLog.Load().Debug().Err(err).Msg("could not remove provision result file")
	}
}

// failProvision persists the result, prints the identifier line, unblocks a
// waiting "ctrld start" via notify, then exits with the stage code. The write
// comes first so the file survives even if logging or notify misbehaves.
func failProvision(r *provisionResult, notify func()) {
	if err := writeProvisionResult(r); err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not persist provision result")
	}
	mainLog.Load().Error().Msg(r.failureLine())
	if notify != nil {
		notify()
	}
	provisionExit(r.ExitCode)
}

// failProvisionUnclassified persists an UNCLASSIFIED result (service stage,
// exit 59) and exits. It is the fallback for a terminal path that predates a
// stable code - a config unmarshal, a file-system or environment failure -
// so support still gets a result file and a stage-scoped exit code instead
// of a bare crash with nothing to read. No terminal path on the
// provisioning boundary may bypass this or an existing classified code.
func failProvisionUnclassified(message string, notify func()) {
	failProvision(newProvisionResult(provisionCodeUnclassified, message, nil, provisionSecrets()...), notify)
}

// failRunUnclassified logs msg on ev, then fails provisioning as UNCLASSIFIED
// and unblocks a waiting "ctrld start" via notify (nil if none). Callers
// return immediately after this call: provisionExit is stubbed out under
// test, so nothing stops execution from falling through otherwise. ev
// carries whatever the caller already chained onto it (for example .Err()),
// so each call site keeps its own log fields.
func failRunUnclassified(ev *ctrld.LogEvent, msg string, notify func()) {
	ev.Msg(msg)
	failProvisionUnclassified(msg, notify)
}

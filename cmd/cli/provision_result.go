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
	provisionStageBootstrap provisionStage = "bootstrap"
	provisionStageListener  provisionStage = "listener"
	provisionStageService   provisionStage = "service"
)

type provisionFailureCode string

const (
	provisionCodeAPIUnreachable      provisionFailureCode = "API_UNREACHABLE"
	provisionCodeAPIRejected         provisionFailureCode = "API_REJECTED"
	provisionCodeAPIDeviceInvalid    provisionFailureCode = "API_DEVICE_INVALID"
	provisionCodeListenerBindFailed  provisionFailureCode = "LISTENER_BIND_FAILED"
	provisionCodeListenerAddrUnavail provisionFailureCode = "LISTENER_CONFIGURED_ADDR_UNAVAILABLE"
	provisionCodeServiceInstall      provisionFailureCode = "SERVICE_INSTALL_FAILED"
	provisionCodeServiceStartFailed  provisionFailureCode = "SERVICE_START_FAILED"
	provisionCodeServiceSelfCheck    provisionFailureCode = "SERVICE_SELFCHECK_FAILED"
)

var allProvisionFailureCodes = []provisionFailureCode{
	provisionCodeAPIUnreachable,
	provisionCodeAPIRejected,
	provisionCodeAPIDeviceInvalid,
	provisionCodeListenerBindFailed,
	provisionCodeListenerAddrUnavail,
	provisionCodeServiceInstall,
	provisionCodeServiceStartFailed,
	provisionCodeServiceSelfCheck,
}

var provisionStageForCode = map[provisionFailureCode]provisionStage{
	provisionCodeAPIUnreachable:      provisionStageBootstrap,
	provisionCodeAPIRejected:         provisionStageBootstrap,
	provisionCodeAPIDeviceInvalid:    provisionStageBootstrap,
	provisionCodeListenerBindFailed:  provisionStageListener,
	provisionCodeListenerAddrUnavail: provisionStageListener,
	provisionCodeServiceInstall:      provisionStageService,
	provisionCodeServiceStartFailed:  provisionStageService,
	provisionCodeServiceSelfCheck:    provisionStageService,
}

// Exit codes are grouped by stage (bootstrap 30-39, listener 40-49, service
// 50-59) so the exit code alone names the failed stage. 0-3 belong to
// "ctrld status" and 126 to the deactivation pin check; never reuse those.
var provisionExitCodeForCode = map[provisionFailureCode]int{
	provisionCodeAPIUnreachable:      30,
	provisionCodeAPIRejected:         31,
	provisionCodeAPIDeviceInvalid:    32,
	provisionCodeListenerBindFailed:  41,
	provisionCodeListenerAddrUnavail: 42,
	provisionCodeServiceInstall:      51,
	provisionCodeServiceStartFailed:  52,
	provisionCodeServiceSelfCheck:    53,
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
	return ctrld.AbsHomeDir(provisionResultFileName)
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

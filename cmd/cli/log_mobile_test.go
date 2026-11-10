package cli

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

const privateQueryLine = "QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A private-name.example."

// The iOS app runs the library at LogLevel -1 with no LogPath, and exports
// ctrld.log. The file must hold no query name, and no resolver UID or
// provision token in any field.
func Test_initInternalLogging_mobileNoticeLogKeepsSecretsOut(t *testing.T) {
	const uid = "1e0rkx9a7tq"
	const token = "org-v1-provisiontoken"
	oldIsMobile := isMobile
	t.Cleanup(func() { isMobile = oldIsMobile })
	isMobile = func() bool { return true }
	_, dir := startInternalLoggingAt(t, -1)
	setJournalSecrets(t, uid, token)

	mainLog.Load().Info().Msg(privateQueryLine)
	mainLog.Load().Error().Str("hostname", uid).Str("note", "token "+token).
		Err(errorString(`Post "https://dns.controld.com/` + uid + `": dial tcp`)).Msg("failed to resolve query")
	mainLog.Load().Warn().Msgf("falling back to direct IPs for %q", uid+".dns.controld.com")

	text := rotatingFileTestContent(t, filepath.Join(dir, logFileName))
	if !strings.Contains(text, "failed to resolve query") {
		t.Fatalf("ctrld.log misses the error line: %s", text)
	}
	for _, secret := range []string{"private-name.example", uid, token} {
		if strings.Contains(text, secret) {
			t.Errorf("ctrld.log contains %q: %s", secret, text)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// At LogLevel -1, a log_path from the configuration with no log_level also
// gets notice lines. A log_level in the configuration still wins.
func Test_initLoggingWithBackup_noticeLevelLogPath(t *testing.T) {
	tests := []struct {
		logLevel      string
		wantQueryName bool
	}{
		{"", false},
		{"info", true},
	}
	for _, tc := range tests {
		t.Run("log_level="+tc.logLevel, func(t *testing.T) {
			path := setupLogPathTest(t)
			cfg.Service.LogLevel = tc.logLevel
			verbose = -1
			initLoggingWithBackup(false)

			mainLog.Load().Info().Msg(privateQueryLine)
			mainLog.Load().Error().Msg("failed to resolve query")

			text := rotatingFileTestContent(t, path)
			if !strings.Contains(text, "failed to resolve query") {
				t.Fatalf("%s misses the error line: %s", path, text)
			}
			if got := strings.Contains(text, "private-name.example"); got != tc.wantQueryName {
				t.Errorf("query name in %s = %v, want %v: %s", path, got, tc.wantQueryName, text)
			}
		})
	}
}

// The app can pass a LogPath, and it exports that file too. The file must
// hold no resolver UID or provision token in any field.
func Test_initLoggingWithBackup_mobileLogPathKeepsSecretsOut(t *testing.T) {
	const uid = "1e0rkx9a7tq"
	const token = "org-v1-provisiontoken"
	path := setupLogPathTest(t)
	oldIsMobile := isMobile
	t.Cleanup(func() { isMobile = oldIsMobile })
	isMobile = func() bool { return true }
	setJournalSecrets(t, uid, token)
	initLoggingWithBackup(false)

	mainLog.Load().Error().Str("hostname", uid).Str("note", "token "+token).
		Err(errorString(`Post "https://dns.controld.com/` + uid + `": dial tcp`)).Msg("failed to resolve query")

	text := rotatingFileTestContent(t, path)
	if !strings.Contains(text, "failed to resolve query") {
		t.Fatalf("%s misses the error line: %s", path, text)
	}
	for _, secret := range []string{uid, token} {
		if strings.Contains(text, secret) {
			t.Errorf("%s contains %q: %s", path, secret, text)
		}
	}
}

// The app can call SetNameservers, which logs, while a start applies its
// configuration on another thread. The redaction of each log line must not
// read the secrets while the start writes them. Run with -race.
func Test_mobileLogFile_redactsWhileStartAppliesConfig(t *testing.T) {
	stubAppConfigGlobals(t)
	oldIsMobile := isMobile
	t.Cleanup(func() { isMobile = oldIsMobile })
	isMobile = func() bool { return true }
	w := mobileLogFile(io.Discard)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_, _ = w.Write([]byte(`{"level":"info","message":"nameservers changed"}` + "\n"))
		}
	}()
	for range 200 {
		applyAppConfig(&AppConfig{CdUID: "1e0rkx9a7tq", ProvisionID: "org-v1-provisiontoken"})
	}
	<-done

	var line bytes.Buffer
	_, _ = mobileLogFile(&line).Write([]byte(`{"message":"uid 1e0rkx9a7tq token org-v1-provisiontoken"}` + "\n"))
	for _, secret := range []string{"1e0rkx9a7tq", "org-v1-provisiontoken"} {
		if strings.Contains(line.String(), secret) {
			t.Errorf("line after applyAppConfig contains %q: %s", secret, line.String())
		}
	}
}

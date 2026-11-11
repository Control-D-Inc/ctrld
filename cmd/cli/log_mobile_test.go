package cli

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// The iOS app runs the library at LogLevel -1 with no LogPath, and exports
// ctrld.log. The file must hold no query name, and no resolver UID or
// provision token in any field.
func Test_initInternalLogging_mobileNoticeLogKeepsSecretsOut(t *testing.T) {
	const uid, token = leakTestUID, leakTestToken
	oldIsMobile, oldOrg := isMobile, cdOrg
	t.Cleanup(func() { isMobile, cdOrg = oldIsMobile, oldOrg })
	isMobile = func() bool { return true }
	origLevel, origVerbose, origMainLog := zerolog.GlobalLevel(), verbose, mainLog.Load()
	t.Cleanup(func() { zerolog.SetGlobalLevel(origLevel); verbose = origVerbose; mainLog.Store(origMainLog) })
	verbose = -1
	initConsoleLogging()
	_, dir := startInternalLoggingAt(t, -1)
	setLogSecrets(t, uid, token)

	mainLog.Load().Info().Msg("QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A private-name.example.")
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

// The app can pass a LogPath, and it exports that file too. On Android, the
// console goes to logcat. Neither may hold the resolver UID or the provision
// token in any field.
func Test_initLoggingWithBackup_mobileLogPathKeepsSecretsOut(t *testing.T) {
	const uid, token = leakTestUID, leakTestToken
	path := setupLogPathTest(t)
	oldIsMobile := isMobile
	t.Cleanup(func() { isMobile = oldIsMobile })
	isMobile = func() bool { return true }
	setLogSecrets(t, uid, token)
	stdout := captureStdout(t)
	initConsoleLogging()
	initLoggingWithBackup(false)

	mainLog.Load().Error().Str("hostname", uid).Str("note", "token "+token).
		Err(errorString(`Post "https://dns.controld.com/` + uid + `": dial tcp`)).Msg("failed to resolve query")

	for sink, text := range map[string]string{path: rotatingFileTestContent(t, path), "stdout": stdout()} {
		if !strings.Contains(text, "failed to resolve query") {
			t.Fatalf("%s misses the error line: %s", sink, text)
		}
		for _, secret := range []string{uid, token} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains %q: %s", sink, secret, text)
			}
		}
	}
}

// The app can call SetNameservers, which logs, while a start applies its
// configuration on another thread. The redaction of each log line must not
// read the secrets while the start writes them. Run with -race.
func Test_logOutput_redactsWhileStartAppliesConfig(t *testing.T) {
	stubAppConfigGlobals(t)
	w := newLogOutput(io.Discard)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_, _ = w.Write([]byte(`{"level":"info","message":"nameservers changed"}` + "\n"))
		}
	}()
	for range 200 {
		applyAppConfig(&AppConfig{CdUID: leakTestUID, ProvisionID: leakTestToken})
	}
	<-done

	var line bytes.Buffer
	_, _ = newLogOutput(&line).Write([]byte(`{"message":"uid ` + leakTestUID + ` token ` + leakTestToken + `"}` + "\n"))
	for _, secret := range []string{leakTestUID, leakTestToken} {
		if strings.Contains(line.String(), secret) {
			t.Errorf("line after applyAppConfig contains %q: %s", secret, line.String())
		}
	}
}

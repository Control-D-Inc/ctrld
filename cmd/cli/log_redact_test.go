package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// The secrets of the no-leak tests. Each test puts them where they do not
// belong: in an error text, in a URL query, in a host name, in a field with
// another name, and in a message about something else.
const (
	leakTestUID   = "1e0rkx9a7tq"
	leakTestToken = "org-v1-provisiontoken"
	// leakTestMixedCaseUID is leakTestUID as a DNS name can carry it. A
	// resolver that randomizes the letter case of a query name (DNS 0x20)
	// changes the case of each letter.
	leakTestMixedCaseUID = "1E0rKx9A7tQ"
)

// leakTestMessage is a line that every sink must keep. It shows that the sink
// got the lines, so a sink with no lines cannot pass.
const leakTestMessage = "could not send log file to ControlD server"

// leakTestUploadError has the shape of an upload that failed before the API
// answered: the URL of the request carries the UID in its query.
func leakTestUploadError() error {
	return fmt.Errorf("SendLogs client.Do: %w", &url.Error{
		Op:  "Post",
		URL: "https://api.controld.com/logs?uid=" + leakTestUID,
		Err: context.Canceled,
	})
}

// logLeakTestLines logs at warn level and higher, so the journal and the
// console keep every line too.
func logLeakTestLines(logger *ctrld.Logger) {
	logger.Error().Msgf(leakTestMessage+": %v", leakTestUploadError())
	logger.Error().Str("peer", leakTestUID).Msg("upload peer")
	logger.Warn().Msgf("falling back to direct IPs for %s", leakTestUID+".dns.controld.com")
	logger.Error().Msgf("enrollment with %s ended", leakTestToken)
	logger.Warn().Msgf("lookup %s.DNS.ControlD.com: no such host", leakTestMixedCaseUID)
	logger.Warn().Msgf("QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A %s.example.com.", leakTestMixedCaseUID)
}

func assertNoLeak(t *testing.T, sink, text string) {
	t.Helper()
	if !strings.Contains(text, leakTestMessage) {
		t.Fatalf("%s misses the line %q: %s", sink, leakTestMessage, text)
	}
	for _, secret := range []string{leakTestUID, leakTestToken} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(secret)) {
			t.Errorf("%s holds %q in some letter case: %s", sink, secret, text)
		}
	}
}

// stubDesktop makes the run a desktop run on every host.
func stubDesktop(t *testing.T) {
	t.Helper()
	origIsMobile := isMobile
	t.Cleanup(func() { isMobile = origIsMobile })
	isMobile = func() bool { return false }
}

// captureStdout points os.Stdout at a pipe. Call it before initConsoleLogging,
// which takes os.Stdout for the console. The returned function puts os.Stdout
// back and returns what the console wrote.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	var out bytes.Buffer
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(&out, r)
	}()
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			os.Stdout = origStdout
			_ = w.Close()
			<-copied
			_ = r.Close()
		})
		return out.String()
	}
	t.Cleanup(func() { finish() })
	return finish
}

// A CLI command logs to the console only. ctrld log send prints the error text
// of the answer there.
func Test_initConsoleLogging_keepsSecretsOutOfStdout(t *testing.T) {
	setupLogSetupTest(t)
	setLogSecrets(t, leakTestUID, leakTestToken)
	stdout := captureStdout(t)
	initConsoleLogging()

	logLeakTestLines(mainLog.Load())

	assertNoLeak(t, "stdout", stdout())
}

// A desktop run in cd mode with no log_path writes the debug file, the memory
// copy that log view and log send read, the log tail subscribers, the
// journal, stdout, and during a start the relay to "ctrld start". A service
// keeps its stdout too: launchd writes it to a file, and systemd to the
// system journal. No sink may hold the UID or the token.
func Test_initLogging_desktopCdModeKeepsSecretsOutOfEverySink(t *testing.T) {
	dir := setupLogSetupTest(t)
	stubDesktop(t)
	setLogSecrets(t, leakTestUID, leakTestToken)
	stdout := captureStdout(t)
	initConsoleLogging()
	relayed := relayConsoleToStart(t)
	p := &prog{cfg: &cfg}
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)
	debugWriter, journalWriter := p.internalWriters()
	if debugWriter == nil || journalWriter == nil {
		t.Fatal("the setup opened no internal streams")
	}
	tail, unsubscribe := debugWriter.Subscribe()
	defer unsubscribe()

	logLeakTestLines(mainLog.Load())

	assertNoLeak(t, logFileName, rotatingFileTestContent(t, filepath.Join(dir, logFileName)))
	assertNoLeak(t, "the debug memory buffer", string(debugWriter.bufferedBytes()))
	assertNoLeak(t, "a log tail subscriber", drainLogTail(tail))
	assertNoLeak(t, journalLogFileName, rotatingFileTestContent(t, filepath.Join(dir, journalLogFileName)))
	assertNoLeak(t, "the journal memory buffer", string(journalWriter.bufferedBytes()))
	assertNoLeak(t, "stdout", stdout())
	assertNoLeak(t, "the relay to ctrld start", relayed())
}

// relayConsoleToStart sends the console to a relay connection as well, the
// way a run does while "ctrld start" waits for it: run builds the console
// core over os.Stdout and the HTTP log client. Call it after
// initConsoleLogging. The returned function closes the connection and
// returns what the relay got.
func relayConsoleToStart(t *testing.T) func() string {
	t.Helper()
	client, server := net.Pipe()
	var relayed bytes.Buffer
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(&relayed, server)
	}()
	consoleWriter = newHumanReadableZapCore(io.MultiWriter(os.Stdout, client), consoleWriterLevel)
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			_ = client.Close()
			<-copied
			_ = server.Close()
		})
		return relayed.String()
	}
	t.Cleanup(func() { finish() })
	return finish
}

// drainLogTail returns the lines that a log tail subscriber got so far.
func drainLogTail(tail <-chan []byte) string {
	var tailed bytes.Buffer
	for {
		select {
		case line := <-tail:
			tailed.Write(line)
		default:
			return tailed.String()
		}
	}
}

// A desktop run with a log_path writes that file and stdout.
func Test_initLogging_desktopLogPathKeepsSecretsOutOfEverySink(t *testing.T) {
	path := setupLogPathTest(t)
	stubLogHeaderNetworkRead(t, "en0")
	stubDesktop(t)
	setLogSecrets(t, leakTestUID, leakTestToken)
	stdout := captureStdout(t)
	initConsoleLogging()
	p := &prog{cfg: &cfg}
	p.initLogging(true)

	logLeakTestLines(mainLog.Load())

	assertNoLeak(t, path, rotatingFileTestContent(t, path))
	assertNoLeak(t, "stdout", stdout())
}

// An older ctrld wrote its log_path file with no redaction. The switch to the
// log_path of the API config copies those lines into the new file, and the
// copy must not carry the secrets.
func Test_switchLogPath_keepsSecretsOutOfTheCarriedLines(t *testing.T) {
	dir := setupLogSetupTest(t)
	stubDesktop(t)
	setLogSecrets(t, leakTestUID, leakTestToken)
	var oldLines bytes.Buffer
	// An older ctrld had no redaction step in front of its sinks.
	oldLogger := &ctrld.Logger{Logger: zap.New(zapcore.NewCore(newJournalEncoder(), zapcore.AddSync(&oldLines), zapcore.DebugLevel))}
	logLeakTestLines(oldLogger)
	if !strings.Contains(oldLines.String(), leakTestUID) {
		t.Fatalf("the old lines hold no UID, so the test proves nothing: %s", oldLines.String())
	}
	oldPath := filepath.Join(dir, "old", "ctrld.log")
	if err := os.MkdirAll(filepath.Dir(oldPath), 0o700); err != nil {
		t.Fatalf("create the old log directory: %v", err)
	}
	if err := os.WriteFile(oldPath, oldLines.Bytes(), 0o600); err != nil {
		t.Fatalf("seed the old log file: %v", err)
	}
	cfg.Service.LogPath = oldPath
	p := &prog{cfg: &cfg}
	// No backup, so the old file keeps the lines of the older ctrld.
	p.initLogging(false)
	t.Cleanup(p.closeInternalLogs)

	newPath := filepath.Join(dir, "logs", "ctrld.log")
	cfg.Service.LogPath = newPath
	p.switchLogPath(oldPath, newPath)

	assertNoLeak(t, newPath, rotatingFileTestContent(t, newPath))
}

// A failed upload answers ctrld log send with its error text, and the CLI
// prints it. The service knows the UID, so the answer must not hold it, in a
// URL or in the text of an API error.
func Test_sendLogsHandler_keepsSecretsOutOfTheAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"url query", leakTestUploadError()},
		{"api error text", errors.New("device " + leakTestUID + " of " + leakTestToken + " is disabled")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := setupMemoryLogReaderTest(t)
			setLogSecrets(t, leakTestUID, leakTestToken)
			if _, err := p.internalLogWriter.Write([]byte("a log line\n")); err != nil {
				t.Fatalf("write the debug buffer: %v", err)
			}
			oldSendLogs := sendLogsToAPI
			t.Cleanup(func() { sendLogsToAPI = oldSendLogs })
			sendLogsToAPI = func(_ context.Context, req *controld.LogsRequest, _ bool) error {
				defer req.Data.Close()
				return tc.err
			}
			cs, err := newControlServer(filepath.Join(t.TempDir(), "control.sock"))
			if err != nil {
				t.Fatalf("newControlServer: %v", err)
			}
			p.cs = cs
			p.registerControlServerHandler()

			recorder := httptest.NewRecorder()
			p.cs.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, sendLogsPath, nil))

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
			}
			var answer logSentResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
				t.Fatalf("decode the answer %q: %v", recorder.Body.String(), err)
			}
			if answer.Error == "" {
				t.Fatalf("the answer holds no error: %s", recorder.Body.String())
			}
			for _, secret := range []string{leakTestUID, leakTestToken} {
				if strings.Contains(recorder.Body.String(), secret) {
					t.Errorf("the answer holds %q: %s", secret, recorder.Body.String())
				}
			}
		})
	}
}

// Test_redactLogLineKeepsAShortClientID puts a two-letter client ID in
// the resolver UID. The keys of a JSON line hold the same letters, and a
// redaction of the client ID would break the line.
func Test_redactLogLineKeepsAShortClientID(t *testing.T) {
	setLogSecrets(t, "uid12345678/os", cdOrg)

	line := string(redactLogLine([]byte(`{"level":"info","os":"darwin","resolver":"uid12345678/os"}`)))

	if !strings.Contains(line, `"os":"darwin"`) {
		t.Fatalf("the redaction changed the os key: %s", line)
	}
	if strings.Contains(line, "uid12345678") {
		t.Fatalf("the redaction kept the resolver uid: %s", line)
	}
}

// Test_redactLogLineStripsEverySchemePath covers the endpoints that carry
// a token in their path with a scheme other than https.
func Test_redactLogLineStripsEverySchemePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`Get "quic://dns.example/org-v1-SECRET0123?dns=pOgBAAAB": timeout`, `Get "quic://dns.example/[redacted]": timeout`},
		{`h3://dns.example/SECRET0123 failed`, `h3://dns.example/[redacted] failed`},
		{`tls://dns.example:853 failed`, `tls://dns.example:853 failed`},
		{`tls://abcdef12.dns.controld.com:853 failed`, `tls://[redacted].dns.controld.com:853 failed`},
		{`quic://abcdef12.dns.controld.dev failed`, `quic://[redacted].dns.controld.dev failed`},
		{`https://freedns.controld.com/p1 failed`, `https://freedns.controld.com/[redacted] failed`},
		{`https://dns.example?uid=SECRET0123 failed`, `https://dns.example/[redacted] failed`},
		{`Post "HTTPS://API.CONTROLD.COM/logs?uid=SECRET0123": EOF`, `Post "HTTPS://API.CONTROLD.COM/[redacted]": EOF`},
		{`Get "https://user:SECRET0123@doh.example/dns-query": EOF`, `Get "https://doh.example/[redacted]": EOF`},
		{`https://user:SECRET0123@doh.example failed`, `https://doh.example failed`},
		{`https://dns.example#SECRET0123 failed`, `https://dns.example/[redacted] failed`},
		{`lookup abcdef12.DNS.ControlD.COM: no such host`, `lookup [redacted].DNS.ControlD.COM: no such host`},
		// A JSON escape inside a URL does not end it. An escaped quote and
		// escaped whitespace do, because they end the URL in the text.
		{`{"message":"https://h.example/a\u0026uid=SECRET0123 x"}`, `{"message":"https://h.example/[redacted] x"}`},
		{`{"message":"https://h.example/a\u0001SECRET0123 x"}`, `{"message":"https://h.example/[redacted] x"}`},
		{`{"message":"Post \"https://h.example/a?b=SECRET0123\": EOF"}`, `{"message":"Post \"https://h.example/[redacted]\": EOF"}`},
		{`{"message":"https://h.example/a?b=SECRET0123\nnext line"}`, `{"message":"https://h.example/[redacted]\nnext line"}`},
	} {
		if got := string(redactLogLine([]byte(tc.in))); got != tc.want {
			t.Errorf("redactLogLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Test_redactLogLineKeepsAShortResolverUID puts a two-letter resolver UID
// in place. The keys of a JSON line hold the same letters, and a redaction of
// the UID would break every log line and the header.
func Test_redactLogLineKeepsAShortResolverUID(t *testing.T) {
	setLogSecrets(t, "os", "")

	const in = `{"level":"info","os":"darwin","message":"loss of service"}`
	if got := string(redactLogLine([]byte(in))); got != in {
		t.Fatalf("redactLogLine(%q) = %q, want the line unchanged", in, got)
	}
}

// setLogSecrets sets cdUID and cdOrg the way a run does, with the copy
// that the log writers read, and puts both back when the test ends.
func setLogSecrets(t testing.TB, uid, org string) {
	t.Helper()
	oldUID, oldOrg := cdUID, cdOrg
	t.Cleanup(func() {
		cdUID, cdOrg = oldUID, oldOrg
		storeLogSecrets()
	})
	cdUID, cdOrg = uid, org
	storeLogSecrets()
}

// redactLogLineUngated is redactLogLine with no literal gates in
// front of its patterns.
func redactLogLineUngated(p []byte) []byte {
	stripped := logURL.ReplaceAllFunc(p, redactURLPath)
	stripped = logControlDHost.ReplaceAll(stripped, []byte(`[redacted]${2}`))
	for _, secret := range logSecrets() {
		stripped = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(string(secret))).ReplaceAll(stripped, []byte("[redacted]"))
	}
	return stripped
}

// The gates only skip a pattern that cannot match, so the redaction keeps
// what it kept with no gates.
func Test_redactLogLineGatesKeepTheOutput(t *testing.T) {
	const uid, token = leakTestUID, leakTestToken
	setLogSecrets(t, uid+"/os", token)
	for _, line := range []string{
		``,
		`{"level":"debug","os":"darwin","message":"QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A www.example.com."}`,
		`{"message":"Post \"https://api.controld.com/logs?uid=` + uid + `\": context canceled"}`,
		`{"message":"dial tcp ` + uid + `.dns.controld.com:853"}`,
		`{"peer":"` + uid + `/os","message":"upload peer"}`,
		`{"message":"token ` + token + ` and ` + token + ` again"}`,
		`{"message":"quic://` + uid + `.dns.controld.dev/` + token + `?dns=AAAB"}`,
		`{"message":"https://dns.controld.com/p1 h3://dns.example/x tls://abcdef12.dns.controld.com:853"}`,
		`{"message":"a bare :// and a bare .dns.controld. suffix"}`,
		`{"message":"lookup ` + leakTestMixedCaseUID + `.DNS.ControlD.com and ` + strings.ToUpper(token) + `"}`,
		`{"message":"HTTPS://user:pass@API.example.com#frag tls://` + uid + `.Dns.Controld.Dev:853"}`,
	} {
		want := string(redactLogLineUngated([]byte(line)))
		if got := string(redactLogLine([]byte(line))); got != want {
			t.Errorf("redactLogLine(%q) = %q, want %q", line, got, want)
		}
	}
}

// BenchmarkRedactLogLine measures the redaction of lines of a busy
// debug log. Every line that the logger writes pays this cost.
func BenchmarkRedactLogLine(b *testing.B) {
	setLogSecrets(b, leakTestUID, leakTestToken)
	for _, bc := range []struct{ name, line string }{
		{"query", `{"level":"debug","time":"2026-11-10T10:00:00.000Z","message":"[a1b2c3] QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A www.example.com. via upstream.0"}`},
		{"answer", `{"level":"debug","time":"2026-11-10T10:00:00.000Z","message":"[a1b2c3] received response of 120 bytes from upstream.0, rcode NOERROR, answers 2"}`},
		{"doh url", `{"level":"debug","time":"2026-11-10T10:00:00.000Z","message":"[a1b2c3] sending doh request to: https://dns.controld.com/` + leakTestUID + `?dns=pOgBAAAB"}`},
		{"mixed case uid", `{"level":"debug","time":"2026-11-10T10:00:00.000Z","message":"[a1b2c3] QUERY: 127.0.0.1:5353 -> 127.0.0.1:53: A ` + leakTestMixedCaseUID + `.example.com."}`},
		{"userinfo url", `{"level":"debug","time":"2026-11-10T10:00:00.000Z","message":"Get \"https://user:pass@doh.example/dns-query?dns=AAAB\": EOF"}`},
	} {
		line := []byte(bc.line + "\n")
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = redactLogLine(line)
			}
		})
	}
}

// A short write is an error for the logger, so the redaction step reports
// the length of the line that it got, not of the line that it wrote.
func Test_logSinkReportsTheOriginalLength(t *testing.T) {
	line := []byte(`{"level":"warn","error":"https://dns.example/org-v1-SECRET0123","message":"state"}` + "\n")
	var buf bytes.Buffer
	n, err := newLogSink(&buf).Write(line)
	if err != nil || n != len(line) {
		t.Fatalf("Write of a line = (%d, %v), want (%d, nil)", n, err, len(line))
	}
	if buf.Len() >= len(line) {
		t.Fatalf("Write wrote no shorter line: %s", buf.String())
	}
}

// The store holds each secret once, and only the values that are long
// enough to redact.
func Test_storeLogSecretsKeepsTheValuesLongEnoughToRedact(t *testing.T) {
	for _, tc := range []struct {
		name, uid, org string
		want           []string
	}{
		{"shortest value", "abcdef", "abcde", []string{"abcdef"}},
		{"uid with no client ID", leakTestUID, leakTestToken, []string{leakTestUID, leakTestToken}},
		{"uid with a client ID", "uid12345678/os", "", []string{"uid12345678/os", "uid12345678"}},
		{"mixed case", leakTestMixedCaseUID, "", []string{leakTestUID}},
		{"no values", "", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setLogSecrets(t, tc.uid, tc.org)
			var got []string
			for _, secret := range logSecrets() {
				got = append(got, string(secret))
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("logSecrets() = %q, want %q", got, tc.want)
			}
			for _, secret := range tc.want {
				if line := string(redactLogLine([]byte("value " + secret))); line != "value [redacted]" {
					t.Errorf("redactLogLine kept %q: %s", secret, line)
				}
			}
		})
	}
}

// The API can echo the UID part of a "<uid>/<client ID>" value alone, and a
// URL query encodes the slash.
func Test_redactLogLineStripsTheUIDPartOfACdValue(t *testing.T) {
	setLogSecrets(t, "uid12345678/os", "")
	for _, line := range []string{
		`{"message":"device uid12345678 is disabled"}`,
		`{"message":"value uid12345678%2Fos"}`,
	} {
		if got := string(redactLogLine([]byte(line))); strings.Contains(got, "uid12345678") {
			t.Errorf("redactLogLine(%q) = %q, want no UID", line, got)
		}
	}
}

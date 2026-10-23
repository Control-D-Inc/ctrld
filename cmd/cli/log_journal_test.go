package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

func Test_journalSetsMarker(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestJSONLogger(&buf)
	journal(logger.Info()).Msg("marked")
	if !bytes.Contains(buf.Bytes(), journalMarker) {
		t.Fatalf("journal event lacks the marker: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"level":"info"`)) {
		t.Fatalf("journal event changed its level: %s", buf.String())
	}
}

// newJournalTestLogger returns a logger whose only core is the journal core.
func newJournalTestLogger(buf *bytes.Buffer) *ctrld.Logger {
	return &ctrld.Logger{Logger: zap.New(newJournalCore(buf))}
}

func Test_journalCoreKeepsWarningsAndMarkedLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  func(logger *ctrld.Logger)
		kept bool
	}{
		{"info with the marker", func(logger *ctrld.Logger) { journal(logger.Info()).Msg("state") }, true},
		{"info without the marker", func(logger *ctrld.Logger) { logger.Info().Msg("state") }, false},
		{"warn without the marker", func(logger *ctrld.Logger) { logger.Warn().Msg("slow") }, true},
		{"debug with the marker", func(logger *ctrld.Logger) { journal(logger.Debug()).Msg("state") }, true},
		// Notice shares its level value with warn, so the journal keeps it.
		{"notice without the marker", func(logger *ctrld.Logger) { logger.Notice().Msg("note") }, true},
		{"error without the marker", func(logger *ctrld.Logger) { logger.Error().Msg("failed") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.log(newJournalTestLogger(&buf))
			if kept := buf.Len() > 0; kept != tc.kept {
				t.Fatalf("kept = %v, want %v, line: %q", kept, tc.kept, buf.String())
			}
		})
	}
}

// Test_journalCoreWriteKeepsMarkedEntryOnly drives the core directly, which
// is the path that zap takes for every line.
func Test_journalCoreWriteKeepsMarkedEntryOnly(t *testing.T) {
	var buf bytes.Buffer
	core := newJournalCore(&buf)
	entry := zapcore.Entry{Level: zapcore.InfoLevel, Message: "state"}

	if err := core.Write(entry, []zapcore.Field{zap.Bool(journalField, true)}); err != nil {
		t.Fatalf("write of a marked entry: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), journalMarker) {
		t.Fatalf("journal holds %q, want the marked line", buf.String())
	}
	marked := buf.Len()

	if err := core.Write(entry, nil); err != nil {
		t.Fatalf("write of a plain entry: %v", err)
	}
	if buf.Len() != marked {
		t.Fatalf("journal kept an unmarked line: %q", buf.String())
	}
}

// Test_journalCoreWithBindsTheMarker proves that a logger with the field
// bound keeps every line, because With moves the field out of Write.
func Test_journalCoreWithBindsTheMarker(t *testing.T) {
	var buf bytes.Buffer
	logger := newJournalTestLogger(&buf).Bool(journalField, true)

	logger.Info().Msg("state")

	if !bytes.Contains(buf.Bytes(), journalMarker) {
		t.Fatalf("journal holds %q, want the bound line", buf.String())
	}
}

// journalDoHError has the shape of a resolver error text: the DoH URL carries
// the resolver path and the packed query.
const journalDoHError = `Get "https://dns.example/org-v1-SECRET0123?dns=pOgBAAAB": dial tcp`

// journalRedactedURL is what the sink keeps of journalDoHError.
const journalRedactedURL = "https://dns.example/[redacted]"

// journalTestLogger returns a logger that writes through the journal sink.
func journalTestLogger(t *testing.T) (*bytes.Buffer, *ctrld.Logger) {
	t.Helper()
	var buf bytes.Buffer
	return &buf, newJournalTestLogger(&buf)
}

func Test_journalCoreRedactsAKeptLine(t *testing.T) {
	buf, logger := journalTestLogger(t)

	logger.Warn().Str("error", journalDoHError).Msg("upstream failed")

	line := buf.String()
	if !strings.Contains(line, journalRedactedURL) {
		t.Fatalf("the sink kept the URL path: %s", line)
	}
	for _, secret := range []string{"SECRET0123", "pOgBAAAB"} {
		if strings.Contains(line, secret) {
			t.Fatalf("the sink kept %q: %s", secret, line)
		}
	}
}

func Test_journalCoreRedactsTheProvisionSecrets(t *testing.T) {
	origCdUID := cdUID
	t.Cleanup(func() { cdUID = origCdUID })
	cdUID = "org-v1-uidofthisdevice"
	buf, logger := journalTestLogger(t)

	logger.Warn().Str("detail", "device "+cdUID+" is gone").Msg("provision failed")

	line := buf.String()
	if strings.Contains(line, cdUID) {
		t.Fatalf("the sink kept the resolver uid: %s", line)
	}
	if !strings.Contains(line, "[redacted]") {
		t.Fatalf("the sink wrote no redaction mark: %s", line)
	}
}

func Test_journalCoreDropsADebugLineWithAURL(t *testing.T) {
	buf, logger := journalTestLogger(t)

	logger.Debug().Str("error", journalDoHError).Msg("upstream failed")

	if buf.Len() != 0 {
		t.Fatalf("the sink kept a debug line: %s", buf.String())
	}
}

func Test_journalCoreRedactsAMarkedInfoLine(t *testing.T) {
	buf, logger := journalTestLogger(t)

	journal(logger.Info()).Str("error", journalDoHError).Msg("upstream failed")

	line := buf.String()
	if !strings.Contains(line, journalRedactedURL) {
		t.Fatalf("the sink kept the URL path: %s", line)
	}
	if !strings.Contains(line, `"level":"info"`) {
		t.Fatalf("the sink changed the level: %s", line)
	}
}

// startInternalLogging drives the real cd mode setup and returns the program
// and the directory that holds the debug file and the journal file.
func startInternalLogging(t *testing.T) (*prog, string) {
	t.Helper()
	origSilent, origCdUID, origHomedir, origVerbose := silent, cdUID, homedir, verbose
	origMainLog := mainLog.Load()
	t.Cleanup(func() {
		silent, cdUID, homedir, verbose = origSilent, origCdUID, origHomedir, origVerbose
		mainLog.Store(origMainLog)
	})
	if origMainLog == nil {
		mainLog.Store(ctrld.NopLogger)
	}

	dir := t.TempDir()
	homedir = dir
	cdUID = "test-uid"
	silent = false
	verbose = 0
	stubHeaderSnapshotSources(t)

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.initInternalLogging(nil)
	// Stop logs through the prog logger, as initLogging wires it.
	p.logger.Store(mainLog.Load())
	t.Cleanup(p.closeInternalLogs)
	return p, dir
}

// Test_initInternalLogging_redactsTheJournalFile drives a cd mode run: support
// downloads the journal file, so it holds the redacted URL, while the debug
// file stays raw for the developer who reads it on the host.
func Test_initInternalLogging_redactsTheJournalFile(t *testing.T) {
	_, dir := startInternalLogging(t)

	mainLog.Load().Warn().Str("error", journalDoHError).Msg("upstream failed")

	journalText := rotatingFileTestContent(t, filepath.Join(dir, journalLogFileName))
	if !strings.Contains(journalText, journalRedactedURL) {
		t.Fatalf("journal file misses the redacted URL: %s", journalText)
	}
	if strings.Contains(journalText, "SECRET0123") {
		t.Fatalf("journal file kept the resolver path: %s", journalText)
	}

	debugText := rotatingFileTestContent(t, filepath.Join(dir, logFileName))
	if !strings.Contains(debugText, "org-v1-SECRET0123?dns=pOgBAAAB") {
		t.Fatalf("debug file lost the raw URL: %s", debugText)
	}
}

// Test_stopClosesTheInternalLogFiles proves that a stopped service leaves no
// open handle on the debug file and the journal file.
func Test_stopClosesTheInternalLogFiles(t *testing.T) {
	origPin := cdDeactivationPin.Load()
	t.Cleanup(func() { cdDeactivationPin.Store(origPin) })
	cdDeactivationPin.Store(defaultDeactivationPin)

	p, _ := startInternalLogging(t)
	p.stopCh = make(chan struct{})
	p.dnsWatcherStopCh = make(chan struct{})
	for _, writer := range []*logWriter{p.internalLogWriter, p.internalJournalWriter} {
		if writer.rotating() == nil {
			t.Fatal("the setup opened no file")
		}
	}

	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	for name, writer := range map[string]*logWriter{
		logFileName:        p.internalLogWriter,
		journalLogFileName: p.internalJournalWriter,
	} {
		if writer.rotating() != nil {
			t.Fatalf("%s stayed open after the stop", name)
		}
	}
}

// Test_redactRetainedLineKeepsAShortClientID puts a two-letter client ID in
// the resolver UID. The keys of a JSON line hold the same letters, and a
// redaction of the client ID would break the line.
func Test_redactRetainedLineKeepsAShortClientID(t *testing.T) {
	origCdUID := cdUID
	t.Cleanup(func() { cdUID = origCdUID })
	cdUID = "uid12345678/os"

	line := string(redactRetainedLine([]byte(`{"level":"info","os":"darwin","resolver":"uid12345678/os"}`)))

	if !strings.Contains(line, `"os":"darwin"`) {
		t.Fatalf("the redaction changed the os key: %s", line)
	}
	if strings.Contains(line, "uid12345678") {
		t.Fatalf("the redaction kept the resolver uid: %s", line)
	}
}

// Test_redactRetainedLineStripsEverySchemePath covers the endpoints that carry
// a token in their path with a scheme other than https.
func Test_redactRetainedLineStripsEverySchemePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`Get "quic://dns.example/org-v1-SECRET0123?dns=pOgBAAAB": timeout`, `Get "quic://dns.example/[redacted]": timeout`},
		{`h3://dns.example/SECRET0123 failed`, `h3://dns.example/[redacted] failed`},
		{`tls://dns.example:853 failed`, `tls://dns.example:853 failed`},
		{`tls://abcdef12.dns.controld.com:853 failed`, `tls://[redacted].dns.controld.com:853 failed`},
		{`quic://abcdef12.dns.controld.dev failed`, `quic://[redacted].dns.controld.dev failed`},
		{`https://freedns.controld.com/p1 failed`, `https://freedns.controld.com/[redacted] failed`},
	} {
		if got := string(redactRetainedLine([]byte(tc.in))); got != tc.want {
			t.Errorf("redactRetainedLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Test_redactRetainedLineKeepsAShortResolverUID puts a two-letter resolver UID
// in place. The keys of a JSON line hold the same letters, and a redaction of
// the UID would break every retained line and the header.
func Test_redactRetainedLineKeepsAShortResolverUID(t *testing.T) {
	origCdUID := cdUID
	t.Cleanup(func() { cdUID = origCdUID })
	cdUID = "os"

	const in = `{"level":"info","os":"darwin","message":"loss of service"}`
	if got := string(redactRetainedLine([]byte(in))); got != in {
		t.Fatalf("redactRetainedLine(%q) = %q, want the line unchanged", in, got)
	}
}

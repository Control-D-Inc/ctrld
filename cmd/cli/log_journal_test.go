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
	setLogSecrets(t, "org-v1-uidofthisdevice", cdOrg)
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
	return startInternalLoggingAt(t, 0)
}

// startInternalLoggingAt is startInternalLogging with the given verbose level.
func startInternalLoggingAt(t *testing.T, level int) (*prog, string) {
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
	verbose = level
	stubHeaderSnapshotSources(t)

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.initInternalLogging(nil)
	// Stop logs through the prog logger, as initLogging wires it.
	p.logger.Store(mainLog.Load())
	t.Cleanup(p.closeInternalLogs)
	return p, dir
}

// Test_initInternalLogging_redactsBothFiles drives a cd mode run. Support
// downloads both files, and the user can share them, so both hold the
// redacted URL.
func Test_initInternalLogging_redactsBothFiles(t *testing.T) {
	_, dir := startInternalLogging(t)

	mainLog.Load().Warn().Str("error", journalDoHError).Msg("upstream failed")

	for _, name := range []string{journalLogFileName, logFileName} {
		text := rotatingFileTestContent(t, filepath.Join(dir, name))
		if !strings.Contains(text, journalRedactedURL) {
			t.Fatalf("%s misses the redacted URL: %s", name, text)
		}
		if strings.Contains(text, "SECRET0123") {
			t.Fatalf("%s kept the resolver path: %s", name, text)
		}
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

// The CLI flags set cdUID and cdOrg before any command runs, so the root
// command must copy them for the log writers.
func Test_rootPreRunStoresTheFlagSecrets(t *testing.T) {
	const token = "org-v1-flagtoken"
	setLogSecrets(t, "", "")
	origVerbose, origMainLog := verbose, mainLog.Load()
	t.Cleanup(func() { verbose = origVerbose; mainLog.Store(origMainLog) })
	// initCLI sets each flag variable to its default, so the token comes
	// after it, as a flag value does.
	rootCmd := initCLI()
	cdOrg = token
	rootCmd.PersistentPreRun(rootCmd, nil)

	line := string(redactLogLine([]byte(`{"message":"token ` + token + `"}`)))
	if strings.Contains(line, token) {
		t.Errorf("line contains the flag token: %s", line)
	}
}

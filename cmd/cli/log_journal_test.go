package cli

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

func Test_journalSetsMarker(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	journal(logger.Info()).Msg("marked")
	if !bytes.Contains(buf.Bytes(), journalMarker) {
		t.Fatalf("journal event lacks the marker: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"level":"info"`)) {
		t.Fatalf("journal event changed its level: %s", buf.String())
	}
}

// journalTestLine has the shape of a serialized event, so the direct write
// path sees the marker where zerolog puts it.
func journalTestLine(marked bool) []byte {
	if marked {
		return []byte(`{"level":"info","` + journalField + `":true,"message":"state"}` + "\n")
	}
	return []byte(`{"level":"info","message":"state"}` + "\n")
}

func Test_journalLevelWriterKeepsWarningsAndMarkedLines(t *testing.T) {
	level := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	for _, tc := range []struct {
		name string
		log  func(logger zerolog.Logger)
		kept bool
	}{
		{"info with the marker", func(logger zerolog.Logger) { journal(logger.Info()).Msg("state") }, true},
		{"info without the marker", func(logger zerolog.Logger) { logger.Info().Msg("state") }, false},
		{"warn without the marker", func(logger zerolog.Logger) { logger.Warn().Msg("slow") }, true},
		{"debug with the marker", func(logger zerolog.Logger) { journal(logger.Debug()).Msg("state") }, true},
		{"notice without the marker", func(logger zerolog.Logger) { logger.Notice().Msg("note") }, false},
		{"error without the marker", func(logger zerolog.Logger) { logger.Error().Msg("failed") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.log(zerolog.New(zerolog.MultiLevelWriter(newJournalLevelWriter(&buf))))
			if kept := buf.Len() > 0; kept != tc.kept {
				t.Fatalf("kept = %v, want %v, line: %q", kept, tc.kept, buf.String())
			}
		})
	}
}

func Test_journalLevelWriterWriteKeepsMarkedLineOnly(t *testing.T) {
	var buf bytes.Buffer
	writer := newJournalLevelWriter(&buf)

	marked := journalTestLine(true)
	n, err := writer.Write(marked)
	if err != nil || n != len(marked) {
		t.Fatalf("write of a marked line = (%d, %v), want (%d, nil)", n, err, len(marked))
	}
	if buf.String() != string(marked) {
		t.Fatalf("journal holds %q, want %q", buf.String(), marked)
	}

	plain := journalTestLine(false)
	n, err = writer.Write(plain)
	if err != nil || n != len(plain) {
		t.Fatalf("write of a plain line = (%d, %v), want (%d, nil)", n, err, len(plain))
	}
	if buf.String() != string(marked) {
		t.Fatalf("journal kept an unmarked line: %q", buf.String())
	}
}

// journalDoHError has the shape of a resolver error text: the DoH URL carries
// the resolver path and the packed query.
const journalDoHError = `Get "https://dns.example/org-v1-SECRET0123?dns=pOgBAAAB": dial tcp`

// journalRedactedURL is what the sink keeps of journalDoHError.
const journalRedactedURL = "https://dns.example/[redacted]"

// journalTestLogger returns a logger that writes through the journal sink.
func journalTestLogger(t *testing.T) (*bytes.Buffer, zerolog.Logger) {
	t.Helper()
	level := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })
	var buf bytes.Buffer
	return &buf, zerolog.New(zerolog.MultiLevelWriter(newJournalLevelWriter(&buf)))
}

func Test_journalLevelWriterRedactsAKeptLine(t *testing.T) {
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

func Test_journalLevelWriterRedactsTheProvisionSecrets(t *testing.T) {
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

func Test_journalLevelWriterDropsADebugLineWithAURL(t *testing.T) {
	buf, logger := journalTestLogger(t)

	logger.Debug().Str("error", journalDoHError).Msg("upstream failed")

	if buf.Len() != 0 {
		t.Fatalf("the sink kept a debug line: %s", buf.String())
	}
}

func Test_journalLevelWriterRedactsAMarkedInfoLine(t *testing.T) {
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

func Test_journalLevelWriterReportsTheOriginalLength(t *testing.T) {
	var buf bytes.Buffer
	writer := newJournalLevelWriter(&buf)
	line := []byte(`{"level":"warn","error":"https://dns.example/org-v1-SECRET0123","message":"state"}` + "\n")

	n, err := writer.WriteLevel(zerolog.WarnLevel, line)

	if err != nil || n != len(line) {
		t.Fatalf("write of a kept line = (%d, %v), want (%d, nil)", n, err, len(line))
	}
	if buf.Len() >= len(line) {
		t.Fatalf("the sink wrote no shorter line: %s", buf.String())
	}
}

// startInternalLogging drives the real cd mode setup and returns the program
// and the directory that holds the debug file and the journal file.
func startInternalLogging(t *testing.T) (*prog, string) {
	t.Helper()
	origSilent, origCdUID, origHomedir, origVerbose := silent, cdUID, homedir, verbose
	origMainLog, origProxyLog := mainLog.Load(), ctrld.ProxyLogger.Load()
	origLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		silent, cdUID, homedir, verbose = origSilent, origCdUID, origHomedir, origVerbose
		mainLog.Store(origMainLog)
		ctrld.ProxyLogger.Store(origProxyLog)
		zerolog.SetGlobalLevel(origLevel)
	})
	if origMainLog == nil {
		discard := zerolog.New(io.Discard)
		mainLog.Store(&discard)
	}

	dir := t.TempDir()
	homedir = dir
	cdUID = "test-uid"
	silent = false
	verbose = 0
	stubHeaderSnapshotSources(t)

	p := &prog{cfg: &ctrld.Config{}}
	p.initInternalLogging(nil)
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

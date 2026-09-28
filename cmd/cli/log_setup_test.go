package cli

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// setupLogSetupTest puts ctrld in cd mode with no log_path and a temporary
// home directory, and puts back every global that the logging setup touches.
// The globals are the reason why no test of this package calls t.Parallel.
func setupLogSetupTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origLogPath, origLogLevel := cfg.Service.LogPath, cfg.Service.LogLevel
	origSilent, origVerbose, origCdUID, origHomedir := silent, verbose, cdUID, homedir
	origConsoleWriter := consoleWriter
	origMainLog := mainLog.Load()
	origLogPathFile, origPendingRotation := logPathFile.Load(), pendingLogPathRotation.Load()
	t.Cleanup(func() {
		if rf := logPathFile.Load(); rf != nil && rf != origLogPathFile {
			_ = rf.close()
		}
		logPathFile.Store(origLogPathFile)
		pendingLogPathRotation.Store(origPendingRotation)
		cfg.Service.LogPath, cfg.Service.LogLevel = origLogPath, origLogLevel
		silent, verbose, cdUID, homedir = origSilent, origVerbose, origCdUID, origHomedir
		consoleWriter = origConsoleWriter
		mainLog.Store(origMainLog)
	})
	cfg.Service.LogPath, cfg.Service.LogLevel = "", "info"
	silent, verbose, cdUID, homedir = false, 0, "", dir
	consoleWriter = newHumanReadableZapCore(io.Discard, ctrld.NoticeLevel)
	mainLog.Store(ctrld.NopLogger)
	logPathFile.Store(nil)
	pendingLogPathRotation.Store(nil)
	stubHeaderSnapshotSources(t)
	stubLogHeaderNetworkRead(t, "en0")
	return dir
}

// Test_initLoggingAfterProvisioning_opensTheJournal drives a --cd-org start:
// the first logging setup runs before the resolver UID is known, and the
// provisioning step then opens the internal streams.
func Test_initLoggingAfterProvisioning_opensTheJournal(t *testing.T) {
	dir := setupLogSetupTest(t)
	p := &prog{cfg: &cfg}
	p.logger.Store(mainLog.Load())
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)

	journalPath := filepath.Join(dir, journalLogFileName)
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("journal exists before the UID is known (stat err = %v)", err)
	}

	cdUID = "provisioned-uid"
	p.initLoggingAfterProvisioning()

	firstLine, headers := logHeaderFileLines(t, journalPath)
	if firstLine.Message != logHeaderMessage || headers != 1 {
		t.Fatalf("journal starts with %q and holds %d headers, want the header once", firstLine.Message, headers)
	}
	mainLog.Load().Warn().Msg("retained after provisioning")
	if content := rotatingFileTestContent(t, journalPath); !strings.Contains(content, "retained after provisioning") {
		t.Fatalf("journal misses the line after provisioning: %s", content)
	}

	p.initLoggingAfterProvisioning()
	if _, headers := logHeaderFileLines(t, journalPath); headers != 1 {
		t.Fatalf("a second call added a header: %d headers", headers)
	}
}

// Test_switchLogPath_leadsTheNewFileAndClosesTheInternalFiles drives the
// log_path that the API config sets after the first logging setup.
func Test_switchLogPath_leadsTheNewFileAndClosesTheInternalFiles(t *testing.T) {
	dir := setupLogSetupTest(t)
	cdUID = "test-uid"
	p := &prog{cfg: &cfg}
	p.logger.Store(mainLog.Load())
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)
	mainLog.Load().Info().Msg("line before the switch")

	newPath := filepath.Join(dir, "logs", "ctrld.log")
	cfg.Service.LogPath = newPath
	p.switchLogPath("", newPath)

	firstLine, headers := logHeaderFileLines(t, newPath)
	if firstLine.Message != logHeaderMessage || headers != 1 {
		t.Fatalf("log_path file starts with %q and holds %d headers, want the header once", firstLine.Message, headers)
	}
	lw, jlw := p.internalWriters()
	if lw.rotating() != nil || jlw.rotating() != nil {
		t.Fatal("the internal files stayed open after the switch")
	}
	if files := p.logHeaderFiles(); !slices.Equal(files, []string{newPath}) {
		t.Fatalf("log_files = %v, want the log_path only", files)
	}
	// cd mode has no local log_path, so the lines of the run stay in the
	// internal debug stream that this call closes.
	if content := rotatingFileTestContent(t, newPath); strings.Contains(content, "line before the switch") {
		t.Fatalf("a line moved although the run had no local log_path: %s", content)
	}
}

// Test_switchLogPath_carriesTheOldFileBelowOneHeader drives a run that already
// wrote a local log_path file. The new file must hold one header, and the
// header must lead the lines that the old file holds.
func Test_switchLogPath_carriesTheOldFileBelowOneHeader(t *testing.T) {
	dir := setupLogSetupTest(t)
	cdUID = "test-uid"
	oldPath := filepath.Join(dir, "old", "ctrld.log")
	cfg.Service.LogPath = oldPath
	p := &prog{cfg: &cfg}
	p.logger.Store(mainLog.Load())
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)
	mainLog.Load().Info().Msg("line before the switch")

	newPath := filepath.Join(dir, "logs", "ctrld.log")
	cfg.Service.LogPath = newPath
	p.switchLogPath(oldPath, newPath)

	firstLine, headers := logHeaderFileLines(t, newPath)
	if firstLine.Message != logHeaderMessage || headers != 1 {
		t.Fatalf("log_path file starts with %q and holds %d headers, want the header once", firstLine.Message, headers)
	}
	if !slices.Equal(firstLine.LogFiles, []string{newPath}) {
		t.Fatalf("header log_files = %v, want the new log_path", firstLine.LogFiles)
	}
	if content := rotatingFileTestContent(t, newPath); !strings.Contains(content, "line before the switch") {
		t.Fatalf("the new file misses the lines of the old file: %s", content)
	}
}

// Test_initLoggingAfterProvisioning_skipsTheGuardedRuns covers the two runs
// that keep no internal files: a run with a local log_path, and a silent run.
// Neither may gain a journal when the provisioning step learns the UID.
func Test_initLoggingAfterProvisioning_skipsTheGuardedRuns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		guard func(t *testing.T, dir string)
	}{
		{"log_path set", func(t *testing.T, dir string) {
			cfg.Service.LogPath = filepath.Join(dir, "operator.log")
		}},
		{"silent set", func(t *testing.T, _ string) { silent = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupLogSetupTest(t)
			tc.guard(t, dir)
			p := &prog{cfg: &cfg}
			p.logger.Store(mainLog.Load())
			p.initLogging(true)
			t.Cleanup(p.closeInternalLogs)

			cdUID = "provisioned-uid"
			p.initLoggingAfterProvisioning()

			journalPath := filepath.Join(dir, journalLogFileName)
			if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
				t.Fatalf("the guarded run opened a journal (stat err = %v)", err)
			}
		})
	}
}

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// Test_needInternalLogging_silent is a regression test for
// https://github.com/Control-D-Inc/ctrld/issues/320: running with --silent must
// not enable internal logging, otherwise ctrld creates and writes
// <homedir>/ctrld.log (and, when verbose==0, resets the global level back to
// debug) despite the user asking for silence.
func Test_needInternalLogging_silent(t *testing.T) {
	origSilent, origCdUID := silent, cdUID
	t.Cleanup(func() { silent, cdUID = origSilent, origCdUID })

	tests := []struct {
		name    string
		silent  bool
		cdUID   string
		logPath string
		want    bool
	}{
		{"silent suppresses internal logging in cd mode", true, "test-uid", "", false},
		{"cd mode enables internal logging", false, "test-uid", "", true},
		{"non-cd mode disabled", false, "", "", false},
		{"explicit log path disables internal logging", false, "test-uid", "/var/log/ctrld.log", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			silent = tt.silent
			cdUID = tt.cdUID
			p := &prog{cfg: &ctrld.Config{}}
			p.logger.Store(mainLog.Load())
			p.cfg.Service.LogPath = tt.logPath
			if got := p.needInternalLogging(); got != tt.want {
				t.Fatalf("needInternalLogging() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_initInternalLogging_silentCreatesNoFile drives the real initInternalLogging
// path and asserts that a --silent --cd run does not create <homedir>/ctrld.log,
// which is the observable failure reported in
// https://github.com/Control-D-Inc/ctrld/issues/320.
func Test_initInternalLogging_silentCreatesNoFile(t *testing.T) {
	origSilent, origCdUID, origHomedir := silent, cdUID, homedir
	t.Cleanup(func() { silent, cdUID, homedir = origSilent, origCdUID, origHomedir })

	dir := t.TempDir()
	homedir = dir
	cdUID = "test-uid" // cd mode, which would otherwise enable internal logging
	silent = true
	stubHeaderSnapshotSources(t)

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.initInternalLogging(nil)

	for _, name := range []string{logFileName, journalLogFileName} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("silent mode must not create %s (stat err = %v)", path, err)
		}
	}
}

// Test_initInternalLogging_createsJournalFile drives a cd mode run and asserts
// that the journal file holds the retained lines only, while the debug file
// holds every line.
func Test_initInternalLogging_createsJournalFile(t *testing.T) {
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
	t.Cleanup(func() {
		p.internalLogWriter.closeLogFile()
		p.internalJournalWriter.closeLogFile()
	})

	debugPath := filepath.Join(dir, logFileName)
	journalPath := filepath.Join(dir, journalLogFileName)
	for _, path := range []string{debugPath, journalPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
	}

	const (
		warnMsg   = "retained warn line"
		markedMsg = "retained marked info line"
		plainMsg  = "dropped plain info line"
	)
	logger := mainLog.Load()
	logger.Warn().Msg(warnMsg)
	journal(logger.Info()).Msg(markedMsg)
	logger.Info().Msg(plainMsg)

	journalText := rotatingFileTestContent(t, journalPath)
	for _, msg := range []string{warnMsg, markedMsg} {
		if !strings.Contains(journalText, msg) {
			t.Fatalf("journal file misses %q: %s", msg, journalText)
		}
	}
	if strings.Contains(journalText, plainMsg) {
		t.Fatalf("journal file kept %q: %s", plainMsg, journalText)
	}

	debugText := rotatingFileTestContent(t, debugPath)
	for _, msg := range []string{warnMsg, markedMsg, plainMsg} {
		if !strings.Contains(debugText, msg) {
			t.Fatalf("debug file misses %q: %s", msg, debugText)
		}
	}
}

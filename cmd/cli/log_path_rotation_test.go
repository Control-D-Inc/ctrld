package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

const (
	logPathTestBackups   = 2
	logPathTestBudgetMB  = 1
	logPathTestLineSize  = 4 * 1024
	logPathTestLineCount = 300
)

// setupLogPathTest points log_path at a temporary file and puts every global
// that initLoggingWithBackup touches back when the test ends. The globals are
// the reason why no test of this package calls t.Parallel.
//
// The temporary directory comes first: its own cleanup removes the directory,
// and a cleanup runs before every cleanup that was added earlier, so the file
// must close before that.
func setupLogPathTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origLogPath, origLogLevel := cfg.Service.LogPath, cfg.Service.LogLevel
	origMaxSizeMB, origMaxBackups := cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups
	origSilent, origVerbose := silent, verbose
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
		cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups = origMaxSizeMB, origMaxBackups
		silent, verbose = origSilent, origVerbose
		consoleWriter = origConsoleWriter
		mainLog.Store(origMainLog)
	})

	backups := logPathTestBackups
	cfg.Service.LogPath = filepath.Join(dir, "ctrld.log")
	cfg.Service.LogLevel = "info"
	cfg.Service.LogMaxSizeMB = logPathTestBudgetMB
	cfg.Service.LogMaxBackups = &backups
	silent, verbose = false, 0
	consoleWriter = newHumanReadableZapCore(io.Discard, ctrld.NoticeLevel)
	mainLog.Store(ctrld.NopLogger)
	logPathFile.Store(nil)
	pendingLogPathRotation.Store(nil)
	return cfg.Service.LogPath
}

func Test_logPathBackupChainOnStart(t *testing.T) {
	path := setupLogPathTest(t)
	if err := os.WriteFile(path, []byte("run1\n"), 0o600); err != nil {
		t.Fatalf("seed log file: %v", err)
	}

	initLoggingWithBackup(true)
	if _, err := logPathFile.Load().Write([]byte("run2\n")); err != nil {
		t.Fatalf("write run2: %v", err)
	}
	initLoggingWithBackup(true)

	newest := rotatingFileTestContent(t, path+".1")
	if !strings.Contains(newest, "run2") {
		t.Fatalf("%s.1 = %q, want the run2 line", path, newest)
	}
	if strings.Contains(newest, "run1") {
		t.Fatalf("%s.1 = %q, want no run1 line", path, newest)
	}
	oldest := rotatingFileTestContent(t, path+".2")
	if !strings.Contains(oldest, "run1") {
		t.Fatalf("%s.2 = %q, want the run1 line", path, oldest)
	}
	current := rotatingFileTestContent(t, path)
	if strings.Contains(current, "run1") || strings.Contains(current, "run2") {
		t.Fatalf("%s = %q, want neither run line", path, current)
	}
}

func Test_logPathRotatesBySize(t *testing.T) {
	path := setupLogPathTest(t)
	initLoggingWithBackup(false)

	line := strings.Repeat("x", logPathTestLineSize)
	for i := 0; i < logPathTestLineCount; i++ {
		mainLog.Load().Info().Msg(line)
	}

	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Fatalf("%s.2 exists although the lines fill one backup (stat err = %v)", path, err)
	}
	want := []string{path + ".1", path}
	if got := logPathFile.Load().paths(); !slices.Equal(got, want) {
		t.Fatalf("paths() = %v, want %v", got, want)
	}

	rotatedLines := 0
	for _, logLine := range strings.Split(rotatingFileTestContent(t, path), "\n") {
		if !strings.Contains(logLine, "Log rotated") {
			continue
		}
		rotatedLines++
		if !hasJournalMarker(logLine) {
			t.Fatalf("Log rotated line %q carries no journal marker", logLine)
		}
	}
	if rotatedLines != 1 {
		t.Fatalf("Log rotated lines in %s = %d, want 1", path, rotatedLines)
	}
}

func Test_logPathHeaderLeadsEveryFile(t *testing.T) {
	path := setupLogPathTest(t)
	stubLogHeaderNetworkRead(t, "en0")
	p := &prog{cfg: &cfg}

	// A start wires its logging twice: once for the config it reads from
	// disk, and once more for the config that the API sends.
	p.initLogging(true)
	p.initLogging(false)

	line := strings.Repeat("x", logPathTestLineSize)
	for i := 0; i < logPathTestLineCount; i++ {
		mainLog.Load().Info().Msg(line)
	}

	for _, name := range []string{path + ".1", path} {
		firstLine, headers := logHeaderFileLines(t, name)
		if firstLine.Message != logHeaderMessage {
			t.Errorf("line 1 of %s = %q, want %q", name, firstLine.Message, logHeaderMessage)
		}
		if headers != 1 {
			t.Errorf("%s holds %d header lines, want 1", name, headers)
		}
	}
}

func Test_logPathStartBackupLogsRotation(t *testing.T) {
	path := setupLogPathTest(t)
	stubLogHeaderNetworkRead(t, "en0")
	if err := os.WriteFile(path, []byte(`{"level":"info","message":"run1"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed log file: %v", err)
	}
	p := &prog{cfg: &cfg}

	p.initLogging(true)

	rotatedLines := 0
	for _, logLine := range strings.Split(rotatingFileTestContent(t, path), "\n") {
		if !strings.Contains(logLine, "Log rotated") {
			continue
		}
		rotatedLines++
		var file string
		if err := json.Unmarshal(parseLogLineFields(t, logLine)["file"], &file); err != nil {
			t.Fatalf("parse the file field of %q: %v", logLine, err)
		}
		if file != path+".1" {
			t.Errorf("file = %q, want %q", file, path+".1")
		}
	}
	if rotatedLines != 1 {
		t.Fatalf("Log rotated lines in %s = %d, want 1", path, rotatedLines)
	}
}

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// setupDebugBudgetTest seeds a debug file with four backups, which is the
// default count, and puts back the two limit keys after the test.
func setupDebugBudgetTest(t *testing.T) string {
	t.Helper()
	dir := setupLogSetupTest(t)
	origSize, origBackups := cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups
	t.Cleanup(func() {
		cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups = origSize, origBackups
	})
	cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups = 0, nil
	debugPath := filepath.Join(dir, logFileName)
	for i := 1; i <= 4; i++ {
		if err := os.WriteFile(debugPath+"."+strconv.Itoa(i), []byte("old run\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return debugPath
}

// assertDebugBudget checks the limits of the open debug file and the backups
// that stay on disk.
func assertDebugBudget(t *testing.T, p *prog, debugPath string, want logBudget) {
	t.Helper()
	debugWriter, _ := p.internalWriters()
	rf := debugWriter.rotating()
	if rf == nil {
		t.Fatal("the debug file is not open")
	}
	rf.mu.Lock()
	got := rf.budget
	rf.mu.Unlock()
	if got != want {
		t.Fatalf("debug budget = %+v, want %+v", got, want)
	}
	for i := 1; i <= 4; i++ {
		_, err := os.Stat(debugPath + "." + strconv.Itoa(i))
		if i <= want.backups && err != nil {
			t.Fatalf("backup %d is gone: %v", i, err)
		}
		if i > want.backups && !os.IsNotExist(err) {
			t.Fatalf("backup %d stays although the limit is %d backups (stat err = %v)", i, want.backups, err)
		}
	}
}

// Test_initLogging_appliesTheLimitsOfTheFetchedConfig drives a first start:
// the debug file opens with the local config, and the API preflight then
// writes the limit keys. The second logging setup must apply them at once, so
// no second restart is necessary.
func Test_initLogging_appliesTheLimitsOfTheFetchedConfig(t *testing.T) {
	debugPath := setupDebugBudgetTest(t)
	cdUID = "test-uid"
	p := &prog{cfg: &cfg}
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)
	defaultBudget, _ := logBudgets(false)
	assertDebugBudget(t, p, debugPath, defaultBudget)

	oneBackup := 1
	cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups = 20, &oneBackup
	p.initLogging(false)

	assertDebugBudget(t, p, debugPath, logBudget{maxSize: 20 << 20, backups: 1})
}

// Test_applyDebugLogBudget_takesTheLimitsOfARefreshedConfig drives a managed
// config refresh, which applies a new config with no restart.
func Test_applyDebugLogBudget_takesTheLimitsOfARefreshedConfig(t *testing.T) {
	debugPath := setupDebugBudgetTest(t)
	cdUID = "test-uid"
	p := &prog{cfg: &cfg}
	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)

	noBackups := 0
	refreshed := ctrld.ServiceConfig{LogMaxSizeMB: 5, LogMaxBackups: &noBackups}
	p.applyDebugLogBudget(debugLogBudget(&refreshed, false))

	assertDebugBudget(t, p, debugPath, logBudget{maxSize: 5 << 20, backups: 0})
}

// Test_applyDebugLogBudget_takesTheLimitsForLogPath checks the log_path file,
// which follows the same two keys. ctrld does not prune its backups, because
// log_path can name a directory that holds the files of other programs.
func Test_applyDebugLogBudget_takesTheLimitsForLogPath(t *testing.T) {
	setupDebugBudgetTest(t)
	logPath := filepath.Join(t.TempDir(), "operator.log")
	cfg.Service.LogPath = logPath
	p := &prog{cfg: &cfg}
	p.initLogging(true)

	want := logBudget{maxSize: 3 << 20, backups: 2}
	p.applyDebugLogBudget(want)

	rf := logPathFile.Load()
	rf.mu.Lock()
	got := rf.budget
	rf.mu.Unlock()
	if got != want {
		t.Fatalf("log_path budget = %+v, want %+v", got, want)
	}
}

// Test_initLogging_reportsTheRotationOfTheStartHeader drives a restart that
// finds the journal close to its limit. The header of the new run rotates the
// file, and the rotation event must reach the files, because support reads it
// to learn where the history of the last run went.
func Test_initLogging_reportsTheRotationOfTheStartHeader(t *testing.T) {
	dir := setupLogSetupTest(t)
	cdUID = "test-uid"
	_, journalBudget := logBudgets(false)
	journalPath := filepath.Join(dir, journalLogFileName)
	oldRun := strings.Repeat("o", int(journalBudget.maxSize)-10) + "\n"
	if err := os.WriteFile(journalPath, []byte(oldRun), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &prog{cfg: &cfg}

	p.initLogging(true)
	t.Cleanup(p.closeInternalLogs)

	if backup := rotatingFileTestContent(t, journalPath+".1"); backup != oldRun {
		t.Fatalf("the journal backup holds %d bytes, want the %d bytes of the old run", len(backup), len(oldRun))
	}
	for _, path := range []string{journalPath, filepath.Join(dir, logFileName)} {
		if content := rotatingFileTestContent(t, path); !strings.Contains(content, "Log rotated") {
			t.Fatalf("%s holds no rotation event: %s", filepath.Base(path), content)
		}
	}
}

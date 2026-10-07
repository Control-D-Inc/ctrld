package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCleanupTestFile creates a file that a cleanup test can watch.
func writeCleanupTestFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("line\n"), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func assertRemoved(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", path, err)
		}
	}
}

func Test_removeLogFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := writeCleanupTestFile(t, filepath.Join(dir, "syslog"))
	chain := []string{
		writeCleanupTestFile(t, filepath.Join(dir, "syslog.1")),
		writeCleanupTestFile(t, filepath.Join(dir, "syslog.2")),
	}
	// A log_path can name a file in a directory of another program, so a
	// number above the configured count belongs to that program.
	foreign := writeCleanupTestFile(t, filepath.Join(dir, "syslog.5"))
	home := t.TempDir()
	internal := []string{
		writeCleanupTestFile(t, filepath.Join(home, logFileName)),
		writeCleanupTestFile(t, filepath.Join(home, journalLogFileName)),
	}
	internalBackups := []string{
		writeCleanupTestFile(t, filepath.Join(home, logFileName+".3")),
		writeCleanupTestFile(t, filepath.Join(home, journalLogFileName+".1")),
	}

	if errs := removeLogFiles(logPath, len(chain), internal); len(errs) > 0 {
		t.Fatalf("removeLogFiles: %v", errs)
	}

	assertRemoved(t, append([]string{logPath}, chain...))
	assertRemoved(t, append(internal, internalBackups...))
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("the cleanup removed %s, which sits above the backup count: %v", foreign, err)
	}
}

func Test_removeLogFilesWithoutALogPath(t *testing.T) {
	home := t.TempDir()
	internal := []string{writeCleanupTestFile(t, filepath.Join(home, logFileName))}
	kept := writeCleanupTestFile(t, filepath.Join(home, "other.log"))

	if errs := removeLogFiles("", 4, internal); len(errs) > 0 {
		t.Fatalf("removeLogFiles: %v", errs)
	}

	assertRemoved(t, internal)
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the cleanup removed %s, which is not a ctrld log: %v", kept, err)
	}
}

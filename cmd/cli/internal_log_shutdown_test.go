package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestFinishRunClosesInternalFilesWithoutServiceStop(t *testing.T) {
	p := &prog{
		cfg: &ctrld.Config{}, runDone: make(chan struct{}), runAbortCh: make(chan struct{}),
		dnsWatcherStopCh:  make(chan struct{}),
		internalLogWriter: newLogWriter(), internalJournalWriter: newSmallLogWriter(),
	}
	p.logger.Store(mainLog.Load())
	var files []*os.File
	var paths []string
	for i, writer := range []*logWriter{p.internalLogWriter, p.internalJournalWriter} {
		path := filepath.Join(t.TempDir(), []string{"debug.log", "journal.log"}[i])
		if err := writer.setLogFile(path, logBudget{maxSize: 4096, backups: 1}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(writer.closeLogFile)
		files = append(files, writer.rotating().f)
		paths = append(paths, path)
	}
	p.onStopped = []func(){func() {
		for _, writer := range []*logWriter{p.internalLogWriter, p.internalJournalWriter} {
			if _, err := writer.Write([]byte("final cleanup\n")); err != nil {
				t.Error(err)
			}
		}
	}}
	close(p.runDone)
	p.finishRun()
	for i, f := range files {
		if _, err := f.Write([]byte("unexpected write\n")); !errors.Is(err, os.ErrClosed) {
			t.Errorf("file %d is not closed: %v", i, err)
		}
		b, err := os.ReadFile(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "final cleanup\n" {
			t.Errorf("file %d lost final cleanup: %q", i, b)
		}
	}
}

package cli

import (
	"os"
	"sync/atomic"
)

// logPathFile is the open log_path file. The header renderer and the log
// readers need it, and both run outside this file.
var logPathFile atomic.Pointer[rotatingFile]

// pendingLogPathRotation holds the rotation of a start-time backup. The
// logger reaches no file at that point, so initLogging reports it later.
var pendingLogPathRotation atomic.Pointer[logRotation]

// openLogPathWriter opens the log_path file of this run and stores it for the
// header renderer and the log readers. It returns nil when no log_path is set.
// A start calls it more than once, so a call for the file that is already open
// keeps that file: a second open would put a second header in it.
func openLogPathWriter(doBackup bool) *rotatingFile {
	logFilePath := normalizeLogFilePath(cfg.Service.LogPath)
	if logFilePath == "" {
		return nil
	}
	budget := debugLogBudget(&cfg.Service)
	rf := logPathFile.Load()
	if rf == nil || rf.currentPath() != logFilePath {
		rf = newLogPathFile(logFilePath, budget)
	} else {
		rf.setBudget(budget)
	}
	if doBackup {
		backupLogPathFile(rf)
	}
	return rf
}

// newLogPathFile opens path and puts it in place of the file of an earlier
// call. A ctrld that cannot write the log file its operator asked for leaves
// no record of the run, so the open failure ends the process.
func newLogPathFile(path string, budget logBudget) *rotatingFile {
	rf, err := newRotatingFile(path, budget, nil)
	if err != nil {
		mainLog.Load().Error().Msgf("failed to create log file: %v", err)
		os.Exit(1)
	}
	rf.onRotate = emitLogRotated
	if old := logPathFile.Swap(rf); old != nil {
		_ = old.close()
	}
	return rf
}

// backupLogPathFile moves the file of an earlier run away, so no run
// overwrites another.
func backupLogPathFile(rf *rotatingFile) {
	if !logFileHasContent(rf.currentPath()) {
		return
	}
	record, err := rf.rotateNow()
	if err != nil {
		mainLog.Load().Error().Msgf("could not backup old log file: %v", err)
		return
	}
	pendingLogPathRotation.Store(record)
}

func logFileHasContent(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

package cli

import (
	"github.com/Control-D-Inc/ctrld"
)

// journalLogFileName is the journal file next to the debug log in the ctrld
// home directory.
const journalLogFileName = "ctrld-journal.log"

// logBudgets splits the disk space by platform. A router keeps the 10 MB total
// that QA measured on an EdgeRouter-X, because its flash is small. A desktop
// holds more, so a log covers more days.
func logBudgets(isRouter bool) (debug, journal logBudget) {
	if isRouter {
		return logBudget{maxSize: 5 << 20, backups: 1}, logBudget{maxSize: 1 << 20, backups: 1}
	}
	return logBudget{maxSize: 10 << 20, backups: 4}, logBudget{maxSize: 2 << 20, backups: 2}
}

const (
	// logMaxSizeMBLimit and logMaxBackupsLimit bound the two keys. The log
	// file opens before ctrld validates its configuration, so a key outside
	// these bounds reaches this code: a size near the largest integer never
	// rotates, and a count of one million backups renames one million files.
	// The validation rules are the first line of defense, and these bounds
	// are the second.
	logMaxSizeMBLimit  = 1024
	logMaxBackupsLimit = 64
)

// debugLogBudget starts from the platform default, so a router keeps its small
// total until an operator asks for more. The two keys size the debug stream
// only. The journal budget stays fixed. A key outside its bounds keeps the
// default.
func debugLogBudget(svc *ctrld.ServiceConfig, isRouter bool) logBudget {
	budget, _ := logBudgets(isRouter)
	if mb := svc.LogMaxSizeMB; mb >= 1 && mb <= logMaxSizeMBLimit {
		budget.maxSize = int64(mb) << 20
	}
	if count := svc.LogMaxBackups; count != nil && *count >= 0 && *count <= logMaxBackupsLimit {
		budget.backups = *count
	}
	return budget
}

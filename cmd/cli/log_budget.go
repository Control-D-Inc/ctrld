package cli

import (
	"github.com/Control-D-Inc/ctrld"
)

// journalLogFileName is the journal file next to the debug log in the ctrld
// home directory.
const journalLogFileName = "ctrld-journal.log"

// logBudgets is the disk space of the two streams. The debug stream takes the
// larger share, so a log covers more days. The journal holds the retained
// lines only, so it stays small.
func logBudgets() (debug, journal logBudget) {
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

// debugLogBudget starts from the default. The two keys size the debug stream
// only. The journal budget stays fixed. A key outside its bounds keeps the
// default.
func debugLogBudget(svc *ctrld.ServiceConfig) logBudget {
	budget, _ := logBudgets()
	if mb := svc.LogMaxSizeMB; mb >= 1 && mb <= logMaxSizeMBLimit {
		budget.maxSize = int64(mb) << 20
	}
	if count := svc.LogMaxBackups; count != nil && *count >= 0 && *count <= logMaxBackupsLimit {
		budget.backups = *count
	}
	return budget
}

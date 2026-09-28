package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func Test_logBudgets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		isRouter    bool
		wantDebug   logBudget
		wantJournal logBudget
	}{
		{"desktop", false, logBudget{maxSize: 10 << 20, backups: 4}, logBudget{maxSize: 2 << 20, backups: 2}},
		{"router", true, logBudget{maxSize: 5 << 20, backups: 1}, logBudget{maxSize: 1 << 20, backups: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			debug, journalStream := logBudgets(tc.isRouter)
			if debug != tc.wantDebug {
				t.Errorf("debug budget = %+v, want %+v", debug, tc.wantDebug)
			}
			if journalStream != tc.wantJournal {
				t.Errorf("journal budget = %+v, want %+v", journalStream, tc.wantJournal)
			}
		})
	}
}

func Test_debugLogBudget(t *testing.T) {
	noBackup, oneBackup := 0, 1
	negativeBackups, tooManyBackups, mostBackups := -1, logMaxBackupsLimit+1, logMaxBackupsLimit
	for _, tc := range []struct {
		name     string
		svc      ctrld.ServiceConfig
		isRouter bool
		want     logBudget
	}{
		{"both keys set", ctrld.ServiceConfig{LogMaxSizeMB: 20, LogMaxBackups: &oneBackup}, false, logBudget{maxSize: 20 << 20, backups: 1}},
		{"size zero keeps the default size", ctrld.ServiceConfig{LogMaxBackups: &oneBackup}, false, logBudget{maxSize: 10 << 20, backups: 1}},
		{"absent backups keep the default count", ctrld.ServiceConfig{LogMaxSizeMB: 20}, false, logBudget{maxSize: 20 << 20, backups: 4}},
		{"zero backups keep no backup file", ctrld.ServiceConfig{LogMaxBackups: &noBackup}, false, logBudget{maxSize: 10 << 20, backups: 0}},
		{"empty config on a desktop", ctrld.ServiceConfig{}, false, logBudget{maxSize: 10 << 20, backups: 4}},
		{"empty config on a router", ctrld.ServiceConfig{}, true, logBudget{maxSize: 5 << 20, backups: 1}},
		{"keys win on a router", ctrld.ServiceConfig{LogMaxSizeMB: 20, LogMaxBackups: &noBackup}, true, logBudget{maxSize: 20 << 20, backups: 0}},
		{"negative size keeps the default size", ctrld.ServiceConfig{LogMaxSizeMB: -1}, false, logBudget{maxSize: 10 << 20, backups: 4}},
		{"size above the limit keeps the default size", ctrld.ServiceConfig{LogMaxSizeMB: logMaxSizeMBLimit + 1}, false, logBudget{maxSize: 10 << 20, backups: 4}},
		{"the largest size the key takes", ctrld.ServiceConfig{LogMaxSizeMB: logMaxSizeMBLimit}, false, logBudget{maxSize: logMaxSizeMBLimit << 20, backups: 4}},
		{"negative backups keep the default count", ctrld.ServiceConfig{LogMaxBackups: &negativeBackups}, false, logBudget{maxSize: 10 << 20, backups: 4}},
		{"backups above the limit keep the default count", ctrld.ServiceConfig{LogMaxBackups: &tooManyBackups}, false, logBudget{maxSize: 10 << 20, backups: 4}},
		{"the largest backup count the key takes", ctrld.ServiceConfig{LogMaxBackups: &mostBackups}, false, logBudget{maxSize: 10 << 20, backups: logMaxBackupsLimit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := debugLogBudget(&tc.svc, tc.isRouter); got != tc.want {
				t.Errorf("debug budget = %+v, want %+v", got, tc.want)
			}
		})
	}
}

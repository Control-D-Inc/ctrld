package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func Test_logBudgets(t *testing.T) {
	debug, journalStream := logBudgets()
	if want := (logBudget{maxSize: 10 << 20, backups: 4}); debug != want {
		t.Errorf("debug budget = %+v, want %+v", debug, want)
	}
	if want := (logBudget{maxSize: 2 << 20, backups: 2}); journalStream != want {
		t.Errorf("journal budget = %+v, want %+v", journalStream, want)
	}
}

func Test_debugLogBudget(t *testing.T) {
	noBackup, oneBackup := 0, 1
	negativeBackups, tooManyBackups, mostBackups := -1, logMaxBackupsLimit+1, logMaxBackupsLimit
	for _, tc := range []struct {
		name string
		svc  ctrld.ServiceConfig
		want logBudget
	}{
		{"both keys set", ctrld.ServiceConfig{LogMaxSizeMB: 20, LogMaxBackups: &oneBackup}, logBudget{maxSize: 20 << 20, backups: 1}},
		{"size zero keeps the default size", ctrld.ServiceConfig{LogMaxBackups: &oneBackup}, logBudget{maxSize: 10 << 20, backups: 1}},
		{"absent backups keep the default count", ctrld.ServiceConfig{LogMaxSizeMB: 20}, logBudget{maxSize: 20 << 20, backups: 4}},
		{"zero backups keep no backup file", ctrld.ServiceConfig{LogMaxBackups: &noBackup}, logBudget{maxSize: 10 << 20, backups: 0}},
		{"empty config", ctrld.ServiceConfig{}, logBudget{maxSize: 10 << 20, backups: 4}},
		{"negative size keeps the default size", ctrld.ServiceConfig{LogMaxSizeMB: -1}, logBudget{maxSize: 10 << 20, backups: 4}},
		{"size above the limit keeps the default size", ctrld.ServiceConfig{LogMaxSizeMB: logMaxSizeMBLimit + 1}, logBudget{maxSize: 10 << 20, backups: 4}},
		{"the largest size the key takes", ctrld.ServiceConfig{LogMaxSizeMB: logMaxSizeMBLimit}, logBudget{maxSize: logMaxSizeMBLimit << 20, backups: 4}},
		{"negative backups keep the default count", ctrld.ServiceConfig{LogMaxBackups: &negativeBackups}, logBudget{maxSize: 10 << 20, backups: 4}},
		{"backups above the limit keep the default count", ctrld.ServiceConfig{LogMaxBackups: &tooManyBackups}, logBudget{maxSize: 10 << 20, backups: 4}},
		{"the largest backup count the key takes", ctrld.ServiceConfig{LogMaxBackups: &mostBackups}, logBudget{maxSize: 10 << 20, backups: logMaxBackupsLimit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := debugLogBudget(&tc.svc); got != tc.want {
				t.Errorf("debug budget = %+v, want %+v", got, tc.want)
			}
		})
	}
}

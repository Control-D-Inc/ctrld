package cli

import (
	"os"
	"path/filepath"
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

	p := &prog{cfg: &ctrld.Config{}}
	p.initInternalLogging(nil)

	logPath := filepath.Join(dir, logFileName)
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("silent mode must not create %s (stat err = %v)", logPath, err)
	}
}

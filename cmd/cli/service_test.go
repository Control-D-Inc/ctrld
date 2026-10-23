package cli

import (
	"errors"
	"strings"
	"testing"
)

func Test_ensureSystemdKillMode(t *testing.T) {
	tests := []struct {
		name       string
		unitFile   string
		wantChange bool
	}{
		{"no KillMode", "[Service]\nExecStart=/bin/sleep 1", true},
		{"not KillMode=process", "[Service]\nExecStart=/bin/sleep 1\nKillMode=mixed", true},
		{"KillMode=process", "[Service]\nExecStart=/bin/sleep 1\nKillMode=process", false},
		{"invalid unit file", "[Service\nExecStart=/bin/sleep 1\nKillMode=process", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, change := ensureSystemdKillMode(strings.NewReader(tc.unitFile)); tc.wantChange != change {
				t.Errorf("ensureSystemdKillMode(%q) = %v, want %v", tc.unitFile, change, tc.wantChange)
			}
		})
	}
}

func TestDoTasksESuccess(t *testing.T) {
	var ran []string
	tasks := []task{
		{func() error { ran = append(ran, "a"); return nil }, false, "a"},
		{func() error { ran = append(ran, "b"); return nil }, true, "b"},
	}
	failedTask, err := doTasksE(tasks)
	if failedTask != "" || err != nil {
		t.Errorf("doTasksE() = (%q, %v), want (\"\", nil)", failedTask, err)
	}
	if got := strings.Join(ran, ","); got != "a,b" {
		t.Errorf("ran tasks %q, want all tasks run in order", got)
	}
}

func TestDoTasksEAbortsOnAbortOnErrorTask(t *testing.T) {
	wantErr := errors.New("install failed")
	var ran []string
	tasks := []task{
		{func() error { ran = append(ran, "Stop"); return nil }, false, "Stop"},
		{func() error { ran = append(ran, "Install"); return wantErr }, true, "Install"},
		{func() error { ran = append(ran, "Start"); return nil }, true, "Start"},
	}
	failedTask, err := doTasksE(tasks)
	if failedTask != "Install" || !errors.Is(err, wantErr) {
		t.Errorf("doTasksE() = (%q, %v), want (\"Install\", %v)", failedTask, err, wantErr)
	}
	if got := strings.Join(ran, ","); got != "Stop,Install" {
		t.Errorf("ran tasks %q, want the run to stop right after the abort", got)
	}
}

func TestDoTasksENonAbortFailureContinues(t *testing.T) {
	var ran []string
	tasks := []task{
		{func() error { ran = append(ran, "a"); return errors.New("a failed") }, false, "a"},
		{func() error { ran = append(ran, "b"); return nil }, true, "b"},
	}
	failedTask, err := doTasksE(tasks)
	if failedTask != "" || err != nil {
		t.Errorf("doTasksE() = (%q, %v), want (\"\", nil) since the failing task did not abort", failedTask, err)
	}
	if got := strings.Join(ran, ","); got != "a,b" {
		t.Errorf("ran tasks %q, want the run to continue past the non-abort failure", got)
	}
}

func TestDoTasksDelegatesToDoTasksE(t *testing.T) {
	if !doTasks([]task{{func() error { return nil }, true, "ok"}}) {
		t.Error("doTasks() = false, want true on success")
	}
	if doTasks([]task{{func() error { return errors.New("boom") }, true, "boom"}}) {
		t.Error("doTasks() = true, want false when an abortOnError task fails")
	}
}

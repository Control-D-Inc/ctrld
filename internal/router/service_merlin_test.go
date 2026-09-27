package router

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kardianos/service"
)

func TestMerlinServiceScriptValidatesPidOwnership(t *testing.T) {
	if strings.Contains(merlinSvcScript, "ps | grep") {
		t.Fatal("Merlin service status must not trust PID existence alone")
	}
	for _, want := range []string{
		`case "$pid" in`,
		`[ -r "/proc/$pid/cmdline" ]`,
		`tr '\000' ' '`,
		`"$exe"|"$exe "*`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service script missing PID ownership check %q", want)
		}
	}
}

func TestMerlinServiceRestartStopsBeforeStarting(t *testing.T) {
	if !strings.Contains(merlinSvcScript, `"$0" stop || exit $?`) {
		t.Fatal("restart must not start a second instance when stop fails")
	}
}

func TestMerlinServiceHookEditorIsIdempotent(t *testing.T) {
	deleteAt := strings.Index(merlinAddLineToScript, `pc_delete "$line" "$file"`)
	appendAt := strings.Index(merlinAddLineToScript, `pc_append "$line" "$file"`)
	if deleteAt < 0 || appendAt < 0 || deleteAt > appendAt {
		t.Fatal("hook editor must delete an existing ctrld line before appending it")
	}
	if !strings.Contains(merlinAddLineToScript, `[ "$mode" = "remove" ] ||`) {
		t.Fatal("hook editor must support remove-only rollback mode")
	}
}

func TestMerlinServiceTemplateRendersExecutableIdentity(t *testing.T) {
	s := &merlinSvc{
		Config: &service.Config{
			Name:       "ctrld",
			Executable: "/jffs/controld/ctrld",
			Arguments:  []string{"run", "--cd", "example"},
		},
	}
	var buf bytes.Buffer
	if err := s.template().Execute(&buf, struct {
		*service.Config
		Path string
	}{s.Config, s.Config.Executable}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		`exe='/jffs/controld/ctrld'`,
		`'/jffs/controld/ctrld' 'run' '--cd' 'example' &`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered Merlin startup script missing %q", want)
		}
	}
}

func TestMerlinServiceTemplatePreservesArgumentBoundaries(t *testing.T) {
	s := &merlinSvc{
		Config: &service.Config{
			Name:       "ctrld",
			Executable: "/jffs/controld/ctrld",
			Arguments:  []string{"run", "--log", "/jffs/log dir/it's.log"},
		},
	}
	var buf bytes.Buffer
	if err := s.template().Execute(&buf, struct {
		*service.Config
		Path string
	}{s.Config, s.Config.Executable}); err != nil {
		t.Fatal(err)
	}
	want := `'/jffs/controld/ctrld' 'run' '--log' '/jffs/log dir/it'"'"'s.log' &`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("rendered command lost shell argument boundaries:\nwant substring: %q\ngot:\n%s", want, buf.String())
	}
}


func TestMerlinServiceStartWaitsForChildExec(t *testing.T) {
	for _, want := range []string{
		"for _ in 1 2 3 4 5; do",
		"if is_running; then",
		"sleep 1",
		`[ "$started" -ne 1 ]`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service start is missing exec-wait safeguard %q", want)
		}
	}
}


func TestMerlinServiceStatusTreatsStoppedAsState(t *testing.T) {
	status, err := merlinServiceStatus([]byte("stopped\n"), os.ErrProcessDone)
	if err != nil {
		t.Fatalf("stopped status returned error: %v", err)
	}
	if status != service.StatusStopped {
		t.Fatalf("status = %v, want %v", status, service.StatusStopped)
	}
}

func TestMerlinServiceStatusRejectsUnexpectedOutput(t *testing.T) {
	if _, err := merlinServiceStatus([]byte("mystery\n"), nil); err == nil {
		t.Fatal("expected unexpected status output to return an error")
	}
}


func TestWriteMerlinStartupScriptPublishesAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	want := []byte("#!/bin/sh\necho ok\n")

	published, err := writeMerlinStartupScript(path, want, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("expected startup script to be published")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("startup script contents mismatch: got %q want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0755 {
		t.Fatalf("startup script mode = %o, want 755", fi.Mode().Perm())
	}
}

func TestWriteMerlinStartupScriptDoesNotClobberExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	original := []byte("user-owned\n")
	if err := os.WriteFile(path, original, 0700); err != nil {
		t.Fatal(err)
	}

	published, err := writeMerlinStartupScript(path, []byte("ctrld-owned\n"), 0755)
	if err == nil {
		t.Fatal("expected publication to fail for existing target")
	}
	if published {
		t.Fatal("existing target must not be reported as ctrld-published")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing target was modified: got %q want %q", got, original)
	}
}


func TestMerlinServiceEventValidatesDnsmasqPidOwnership(t *testing.T) {
	for _, want := range []string{
		`case "$dnsmasq_pid" in`,
		`[ -r "/proc/$dnsmasq_pid/cmdline" ]`,
		`tr '\000' '\n'`,
		`dnsmasq|*/dnsmasq) kill "$dnsmasq_pid"`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service_event missing dnsmasq PID ownership check %q", want)
		}
	}
}

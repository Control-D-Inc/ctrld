package router

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
		`is_running_pid "$pid"`,
		`kill "$pid"`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service script missing PID ownership check %q", want)
		}
	}
	if strings.Contains(merlinSvcScript, `kill "$(get_pid)"`) {
		t.Fatal("stop must kill the same PID whose ctrld ownership was validated")
	}
}

func TestMerlinServiceRestartStopsBeforeStarting(t *testing.T) {
	if !strings.Contains(merlinSvcScript, `"$0" stop || exit $?`) {
		t.Fatal("restart must not start a second instance when stop fails")
	}
}

func TestMerlinServiceHookEditorIsIdempotent(t *testing.T) {
	for _, want := range []string{
		`if grep -qxF "$line" "$file"; then`,
		`grep_status=$?`,
		`[ "$grep_status" -eq 1 ] || exit "$grep_status"`,
		`pc_append "$line" "$file" || exit $?`,
		`printf 'added\n'`,
	} {
		if !strings.Contains(merlinAddLineToScript, want) {
			t.Fatalf("hook editor missing idempotent append signal %q", want)
		}
	}
	for _, script := range []string{merlinAddLineToScript, merlinRemoveLineFromScript} {
		if !strings.Contains(script, `sed -i "/^$pattern$/d" "$file"`) {
			t.Fatal("hook removal must match only ctrld's complete line")
		}
	}
	if strings.Contains(merlinAddLineToScript, `pc_delete "$line" "$file"`) {
		t.Fatal("install path must not destructively delete a working hook before append")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystems do not expose POSIX executable mode semantics")
	}
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


func TestValidateMerlinSharedHookPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin shared hooks are POSIX shell files and executable-bit checks are Unix-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "services-start")

	exists, err := validateMerlinSharedHookPath(path, true)
	if err != nil || exists {
		t.Fatalf("missing hook = (%v, %v), want (false, nil)", exists, err)
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := validateMerlinSharedHookPath(path, true); err == nil {
		t.Fatal("expected non-executable shared hook to be rejected")
	}
	if exists, err := validateMerlinSharedHookPath(path, false); err != nil || !exists {
		t.Fatalf("regular non-executable hook should be editable for uninstall: (%v, %v)", exists, err)
	}

	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if exists, err := validateMerlinSharedHookPath(path, true); err != nil || !exists {
		t.Fatalf("executable shared hook rejected: (%v, %v)", exists, err)
	}

	link := filepath.Join(dir, "services-start-link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := validateMerlinSharedHookPath(link, false); err == nil {
			t.Fatal("expected shared-hook symlink to be rejected")
		}
	}
}


func TestMerlinStartupHookLinesQuoteConfigPath(t *testing.T) {
	start, event := merlinStartupHookLines("/jffs/my dir/it's ctrld.startup")
	wantPrefix := `'/jffs/my dir/it'"'"'s ctrld.startup'`
	if start != wantPrefix+" start" {
		t.Fatalf("start hook = %q", start)
	}
	if event != wantPrefix+` service_event "$1" "$2"` {
		t.Fatalf("service-event hook = %q", event)
	}
}


func TestMerlinLegacyStartupHookLinesRemainRemovable(t *testing.T) {
	path := "/jffs/controld/ctrld.startup"
	start, event := merlinLegacyStartupHookLines(path)
	if start != path+" start" {
		t.Fatalf("legacy start hook = %q", start)
	}
	if event != path+` service_event "$1" "$2"` {
		t.Fatalf("legacy service-event hook = %q", event)
	}
}


func TestPrepareExistingMerlinStartupScriptRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "ctrld.startup")
	if err := os.WriteFile(target, []byte("private\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if exists, err := prepareExistingMerlinStartupScript(link, []byte("private\n"), nil); err == nil || !exists {
		t.Fatalf("symlink startup script = (exists %v, err %v), want exists=true and error", exists, err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "private\n" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestPrepareExistingMerlinStartupScriptRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.startup")
	want := []byte("#!/bin/sh\n")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	exists, err := prepareExistingMerlinStartupScript(path, want, want)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("regular startup script reported missing")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("regular startup script = %q, want %q", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != 0755 {
			t.Fatalf("regular startup script mode = %o, want 755", gotMode)
		}
	}
}

func TestPrepareExistingMerlinStartupScriptMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.startup")
	exists, err := prepareExistingMerlinStartupScript(path, []byte("#!/bin/sh\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("missing startup script reported as existing")
	}
}


func TestPrepareExistingMerlinStartupScriptMigratesExactLegacyTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin startup scripts are Linux-specific")
	}
	s := &merlinSvc{
		Config: &service.Config{
			Name:       "ctrld",
			Executable: "/jffs/controld/ctrld",
			Arguments:  []string{"run", "--cd", "example"},
		},
	}
	current, legacy, err := s.renderStartupScripts(s.Config.Executable)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, legacy) {
		t.Fatal("current and legacy templates unexpectedly match")
	}

	path := filepath.Join(t.TempDir(), "ctrld.startup")
	if err := os.WriteFile(path, legacy, 0755); err != nil {
		t.Fatal(err)
	}
	exists, err := prepareExistingMerlinStartupScript(path, current, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("legacy startup script reported missing")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, current) {
		t.Fatalf("legacy startup script was not migrated exactly")
	}
}

func TestPrepareExistingMerlinStartupScriptRejectsUnknownCustomization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.startup")
	custom := []byte("#!/bin/sh\necho user-custom\n")
	if err := os.WriteFile(path, custom, 0755); err != nil {
		t.Fatal(err)
	}
	if exists, err := prepareExistingMerlinStartupScript(
		path,
		[]byte("#!/bin/sh\necho current\n"),
		[]byte("#!/bin/sh\necho legacy\n"),
	); err == nil || !exists {
		t.Fatalf("custom startup script = (exists %v, err %v), want exists=true and error", exists, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, custom) {
		t.Fatalf("custom startup script was modified: got %q want %q", got, custom)
	}
}


func TestRefreshMerlinStartupScriptRecoversInstalledLegacyArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin startup scripts are Linux-specific")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "ctrld")

	installedSvc := &merlinSvc{Config: &service.Config{
		Name:       "ctrld",
		Executable: exe,
		Arguments:  []string{"run", "--cd=abcd1234", "--config=/jffs/controld/ctrld.toml"},
	}}
	_, legacy, err := installedSvc.renderStartupScripts(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".startup", legacy, 0755); err != nil {
		t.Fatal(err)
	}

	// Normal restart/upgrade service construction does not carry the original
	// installed Arguments.
	lifecycleSvc := &merlinSvc{Config: &service.Config{
		Name:       "ctrld",
		Executable: exe,
	}}
	if err := lifecycleSvc.refreshMerlinStartupScript(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(exe + ".startup")
	if err != nil {
		t.Fatal(err)
	}
	if !merlinStartupScriptHasMarker(got) {
		t.Fatal("migrated startup script is missing the current ctrld marker")
	}
	for _, want := range []string{
		merlinShellQuote("--cd=abcd1234"),
		merlinShellQuote("--config=/jffs/controld/ctrld.toml"),
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("migrated startup script lost installed argument %q", want)
		}
	}
}

func TestRefreshMerlinStartupScriptForExecutableMigratesFromNewBinaryPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin startup scripts are Linux-specific")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "ctrld")
	installedSvc := &merlinSvc{Config: &service.Config{
		Name:       "ctrld",
		Executable: exe,
		Arguments:  []string{"run", "--cd=upgrade-device", "--config=/jffs/controld/ctrld.toml"},
	}}
	current, legacy, err := installedSvc.renderStartupScripts(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe+".startup", legacy, 0755); err != nil {
		t.Fatal(err)
	}

	// This models the first process started from the just-downloaded binary:
	// it has only its executable path, not the old process's service.Config.
	if err := refreshMerlinStartupScriptForExecutable(exe); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(exe + ".startup")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, current) {
		t.Fatalf("new-binary migration mismatch\nwant:\n%s\ngot:\n%s", current, got)
	}
}

func TestRefreshMerlinStartupScriptLeavesCurrentMarkedScriptUntouched(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ctrld")
	path := exe + ".startup"
	original := []byte("#!/bin/sh\n" + merlinSvcScriptMarker + "\necho custom-current-body\n")
	if err := os.WriteFile(path, original, 0700); err != nil {
		t.Fatal(err)
	}

	s := &merlinSvc{Config: &service.Config{Name: "ctrld", Executable: exe}}
	if err := s.refreshMerlinStartupScript(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("current marked script was rewritten:\nwant: %q\ngot:  %q", original, got)
	}
}

func TestRefreshMerlinStartupScriptLeavesUnknownCustomizationUntouched(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ctrld")
	path := exe + ".startup"
	original := []byte("#!/bin/sh\necho user-custom-startup\n")
	if err := os.WriteFile(path, original, 0755); err != nil {
		t.Fatal(err)
	}

	s := &merlinSvc{Config: &service.Config{Name: "ctrld", Executable: exe}}
	if err := s.refreshMerlinStartupScript(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("unknown customized script was modified:\nwant: %q\ngot:  %q", original, got)
	}
}

func TestRecoverLegacyMerlinServiceConfigRejectsWrongExecutable(t *testing.T) {
	base := &service.Config{Name: "ctrld", Executable: "/jffs/controld/ctrld"}
	buf := []byte("#!/bin/sh\ncmd=\"/tmp/other run --cd=abc\"\n")
	if _, ok := recoverLegacyMerlinServiceConfig(buf, base, base.Executable); ok {
		t.Fatal("legacy config recovery accepted a different executable")
	}
}


func TestCanStartMerlinStartupAfterMigrationError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin startup scripts are Linux-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	legacy := []byte("#!/bin/sh\necho legacy\n")

	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{"exact legacy", legacy, true},
		{"current marked", []byte("#!/bin/sh\n" + merlinSvcScriptMarker + "\necho current\n"), true},
		{"custom", []byte("#!/bin/sh\necho custom\n"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.body, 0755); err != nil {
				t.Fatal(err)
			}
			got, err := canStartMerlinStartupAfterMigrationError(path, legacy)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("canStart = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanStartMerlinStartupAfterMigrationErrorMissingPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin startup scripts are Linux-specific")
	}
	got, err := canStartMerlinStartupAfterMigrationError(filepath.Join(t.TempDir(), "missing.startup"), []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("missing startup path must not be considered safe to start")
	}
}

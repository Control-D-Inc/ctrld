package merlin

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

func legacyMerlinPostConf(orig string) string {
	generated := strings.Join([]string{
		dnsmasq.CtrldMarker,
		"#!/bin/sh",
		"echo ctrld-legacy",
	}, "\n")
	return strings.Join([]string{
		generated,
		"\n",
		dnsmasq.MerlinPostConfMarker,
		"\n",
		orig,
	}, "\n")
}

func Test_merlinParsePostConf(t *testing.T) {
	origContent := "# foo"

	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"empty", "", ""},
		{"no ctrld", origContent, origContent},
		{"ctrld with data", legacyMerlinPostConf(origContent), origContent},
		{"ctrld without data", legacyMerlinPostConf(""), ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			//t.Parallel()
			if got := merlinParsePostConf([]byte(tc.data)); !bytes.Equal(got, []byte(tc.expected)) {
				t.Errorf("unexpected result, want: %q, got: %q", tc.expected, string(got))
			}
		})
	}
}


func Test_merlinParsePostConfMarkedBlock(t *testing.T) {
	input := "#!/bin/sh\n# BEGIN ctrld\necho ctrld\n# END ctrld\n\necho custom\n"
	want := "#!/bin/sh\n\necho custom\n"

	if got := string(merlinParsePostConf([]byte(input))); got != want {
		t.Fatalf("unexpected result, want %q, got %q", want, got)
	}
}

func Test_merlinUpsertPostConfPreservesExistingContent(t *testing.T) {
	orig := []byte("#!/bin/sh\n\necho before\necho after\n")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")

	got := merlinUpsertPostConf(orig, block)

	if bytes.Count(got, []byte(dnsmasq.MerlinPostConfBeginMarker)) != 1 {
		t.Fatalf("expected exactly one ctrld block, got:\n%s", got)
	}
	if !bytes.Contains(got, []byte("echo before\necho after")) {
		t.Fatalf("existing hook content was not preserved:\n%s", got)
	}
	if !bytes.HasPrefix(got, []byte("#!/bin/sh\n")) {
		t.Fatalf("existing shebang was not preserved:\n%s", got)
	}

	gotAgain := merlinUpsertPostConf(got, block)
	if !bytes.Equal(got, gotAgain) {
		t.Fatalf("upsert is not idempotent:\nfirst:\n%s\nsecond:\n%s", got, gotAgain)
	}
}

func Test_merlinPostConfDoesNotExitHostHook(t *testing.T) {
	if strings.Contains(dnsmasq.MerlinPostConfTmpl, "exit 0") {
		t.Fatal("ctrld postconf block must not terminate the enclosing Merlin hook")
	}
	trimmed := strings.TrimSpace(dnsmasq.MerlinPostConfTmpl)
	if !strings.HasPrefix(trimmed, "(\n") || !strings.HasSuffix(trimmed, "\n)") {
		t.Fatal("ctrld postconf block must run in a newline-delimited subshell to isolate shared-hook variables")
	}
	if strings.Contains(dnsmasq.MerlinPostConfTmpl, `\nconfig_file`) {
		t.Fatal("raw Merlin postconf template must contain a real newline, not a literal \\n escape")
	}
}

func Test_merlinLegacyMigrationPreservesPrependedContent(t *testing.T) {
	legacy := "echo addon-before\n" + legacyMerlinPostConf("echo addon-after")
	block := []byte("# BEGIN ctrld\necho ctrld-new\n# END ctrld")

	got := string(merlinUpsertPostConf([]byte(legacy), block))
	want := "echo addon-before\n# BEGIN ctrld\necho ctrld-new\n# END ctrld\necho addon-after"
	if got != want {
		t.Fatalf("legacy migration changed unrelated content or position:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func Test_merlinUpsertPostConfKeepsExistingBlockPosition(t *testing.T) {
	input := []byte("#!/bin/sh\n\necho addon-before\n# BEGIN ctrld\necho old\n# END ctrld\necho addon-after\n")
	block := []byte("# BEGIN ctrld\necho new\n# END ctrld")

	got := string(merlinUpsertPostConf(input, block))
	want := "#!/bin/sh\n\necho addon-before\n# BEGIN ctrld\necho new\n# END ctrld\necho addon-after\n"
	if got != want {
		t.Fatalf("managed block moved relative to addon content:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func Test_merlinParsePostConfPreservesLegacyPrefixAndSuffix(t *testing.T) {
	input := "echo addon-before\n" + legacyMerlinPostConf("echo addon-after")
	want := "echo addon-before\necho addon-after"

	if got := string(merlinParsePostConf([]byte(input))); got != want {
		t.Fatalf("legacy cleanup changed unrelated content:\nwant: %q\ngot:  %q", want, got)
	}
}


func Test_cleanupDnsmasqPostconfPreservesPreexistingStub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	installed := merlinUpsertPostConf([]byte("#!/bin/sh\n"), block)
	if err := os.WriteFile(path, installed, 0750); err != nil {
		t.Fatal(err)
	}

	if err := cleanupDnsmasqPostconf(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pre-existing hook stub was removed: %v", err)
	}
	if string(got) != "#!/bin/sh\n" {
		t.Fatalf("unexpected restored stub: %q", got)
	}
}

func Test_cleanupDnsmasqPostconfLeavesEmptyPathWhenCtrldCreatedHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	if err := os.WriteFile(path, merlinUpsertPostConf(nil, block), 0750); err != nil {
		t.Fatal(err)
	}

	if err := cleanupDnsmasqPostconf(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cleanup removed shared hook path: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected cleaned ctrld-created hook: %q", got)
	}
}

func Test_atomicWriteFilePreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "dnsmasq.postconf")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}

	if err := atomicWriteFile(link, []byte("new"), 0750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("atomicWriteFile replaced the symlink instead of its target")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target content = %q, want %q", got, "new")
	}
}


func Test_merlinPostConfMarkersMustBeCompleteLines(t *testing.T) {
	input := []byte("#!/bin/sh\npattern='# BEGIN ctrld'\nend='# END ctrld'\necho untouched\n")
	if _, _, _, ok := merlinPostConfBlock(input); ok {
		t.Fatal("marker substrings inside unrelated shell lines must not be treated as ctrld ownership")
	}
	if got := merlinParsePostConf(input); !bytes.Equal(got, input) {
		t.Fatalf("unrelated hook content changed:\nwant: %q\ngot:  %q", input, got)
	}
}

func Test_merlinLegacyMarkersMustBeCompleteLines(t *testing.T) {
	input := []byte("#!/bin/sh\nheader='# GENERATED BY ctrld - DO NOT MODIFY'\neof='# GENERATED BY ctrld - EOF'\necho untouched\n")
	if _, _, _, ok := merlinPostConfBlock(input); ok {
		t.Fatal("legacy marker substrings inside unrelated shell lines must not be treated as ctrld ownership")
	}
	if got := merlinParsePostConf(input); !bytes.Equal(got, input) {
		t.Fatalf("unrelated legacy-like hook content changed:\nwant: %q\ngot:  %q", input, got)
	}
}

func Test_merlinPostConfRoundTripRestoresOriginalBytes(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("\n\n"),
		[]byte("echo no-shebang\n"),
		[]byte("#!/bin/sh"),
		[]byte("#!/bin/sh\n"),
		[]byte("#!/bin/sh\n\necho custom\n"),
		[]byte("#!/bin/sh\n# comment\necho one\necho two\n"),
		[]byte("#!/bin/sh\r\n\r\necho crlf\r\n"),
	}

	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	for _, orig := range tests {
		installed := merlinUpsertPostConf(orig, block)
		cleaned := merlinParsePostConf(installed)
		if !bytes.Equal(cleaned, orig) {
			t.Fatalf("setup/cleanup did not restore original bytes:\norig: %q\ninstalled: %q\ncleaned: %q", orig, installed, cleaned)
		}
	}
}


func Test_merlinLegacyCleanupRestoresShebangAtByteZero(t *testing.T) {
	orig := "#!/bin/sh\necho original\n"
	legacy := legacyMerlinPostConf(orig)
	got := merlinParsePostConf([]byte(legacy))
	if string(got) != orig {
		t.Fatalf("legacy cleanup did not restore original hook exactly:\nwant: %q\ngot:  %q", orig, got)
	}
	if !bytes.HasPrefix(got, []byte("#!")) {
		t.Fatalf("restored hook lost shebang at byte zero: %q", got)
	}
}

func Test_merlinSyntheticShebangIsOwnedAndReversible(t *testing.T) {
	orig := []byte("echo third-party-without-shebang\n")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	installed := merlinUpsertPostConf(orig, block)

	if !bytes.HasPrefix(installed, []byte("#!/bin/sh\n")) {
		t.Fatalf("synthetic shebang missing: %q", installed)
	}
	if !bytes.Contains(installed, []byte(dnsmasq.MerlinSyntheticShebangMarker)) {
		t.Fatalf("synthetic shebang ownership marker missing: %q", installed)
	}
	if got := merlinParsePostConf(installed); !bytes.Equal(got, orig) {
		t.Fatalf("cleanup did not restore original bytes:\nwant: %q\ngot:  %q", orig, got)
	}
}

func Test_merlinLegacyEmptyHookCanBeReinstalled(t *testing.T) {
	legacy := []byte(legacyMerlinPostConf(""))
	clean := merlinParsePostConf(legacy)
	if len(clean) != 0 {
		t.Fatalf("legacy cleanup = %q, want empty hook", clean)
	}

	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	reinstalled := merlinUpsertPostConf(clean, block)
	if !bytes.HasPrefix(reinstalled, []byte("#!/bin/sh\n")) ||
		!bytes.Contains(reinstalled, []byte(dnsmasq.MerlinSyntheticShebangMarker)) {
		t.Fatalf("empty legacy hook was not safely reinstalled: %q", reinstalled)
	}
	if got := merlinParsePostConf(reinstalled); len(got) != 0 {
		t.Fatalf("reinstalled hook did not round-trip to empty: %q", got)
	}
}

func Test_revalidateMerlinHookUpdateDetectsContentChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	orig := []byte("#!/bin/sh\necho original\n")
	if err := os.WriteFile(path, orig, 0750); err != nil {
		t.Fatal(err)
	}
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	update, err := prepareMerlinHookUpdate(path, block)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho changed\n"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := revalidateMerlinHookUpdate(update); err == nil {
		t.Fatal("expected revalidation failure after content change")
	}
}

func Test_revalidateMerlinHookUpdateDetectsAppearedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	update, err := prepareMerlinHookUpdate(path, block)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho addon\n"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := revalidateMerlinHookUpdate(update); err == nil {
		t.Fatal("expected revalidation failure when a missing hook appears")
	}
}

func Test_revalidateMerlinHookUpdateDetectsDisappearedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0750); err != nil {
		t.Fatal(err)
	}
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	update, err := prepareMerlinHookUpdate(path, block)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := revalidateMerlinHookUpdate(update); err == nil {
		t.Fatal("expected revalidation failure when a hook disappears")
	}
}

func Test_atomicWriteFilePreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not preserved by Windows filesystems")
	}
	for _, mode := range []os.FileMode{0700, 0770} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
			if err := os.WriteFile(path, []byte("old"), mode); err != nil {
				t.Fatal(err)
			}
			if err := atomicWriteFile(path, []byte("new"), 0750); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != mode.Perm() {
				t.Fatalf("mode = %v, want %v", got, mode.Perm())
			}
		})
	}
}

func Test_cleanupPreparationRevalidatesBeforeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	managed := []byte("#!/bin/sh\n# BEGIN ctrld\necho managed\n# END ctrld\necho addon\n")
	if err := os.WriteFile(path, managed, 0750); err != nil {
		t.Fatal(err)
	}
	update, err := prepareMerlinHookCleanup(path)
	if err != nil {
		t.Fatal(err)
	}
	if update == nil {
		t.Fatal("expected cleanup update")
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho addon-changed\n"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := revalidateMerlinHookUpdate(*update); err == nil {
		t.Fatal("expected cleanup revalidation failure after external modification")
	}
}

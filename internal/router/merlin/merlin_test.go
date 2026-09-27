package merlin

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
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

func Test_writeMerlinHookUpdatesPreflightsAllPaths(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "dnsmasq.postconf")
	second := filepath.Join(dir, "dnsmasq-sdn.postconf")
	orig := []byte("#!/bin/sh\necho untouched\n")
	if err := os.WriteFile(first, orig, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0755); err != nil {
		t.Fatal(err)
	}

	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	if err := writeMerlinHookUpdates([]string{first, second}, block); err == nil {
		t.Fatal("expected second-path preflight error")
	}
	got, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("first hook changed before second path passed preflight:\nwant: %q\ngot:  %q", orig, got)
	}
}

func Test_writeMerlinHookUpdatesRollsBackPartialWrites(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "dnsmasq.postconf")
	second := filepath.Join(dir, "dnsmasq-sdn.postconf")
	orig := []byte("#!/bin/sh\necho original\n")
	if err := os.WriteFile(first, orig, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("#!/bin/sh\necho second\n"), 0750); err != nil {
		t.Fatal(err)
	}

	writes := 0
	writeFile := func(path string, data []byte, mode os.FileMode) error {
		writes++
		if writes == 2 {
			return os.ErrPermission
		}
		return atomicWriteFile(path, data, mode)
	}

	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	if err := writeMerlinHookUpdatesWith([]string{first, second}, block, writeFile); err == nil {
		t.Fatal("expected second write failure")
	}
	got, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("first hook was not rolled back:\nwant: %q\ngot:  %q", orig, got)
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

func Test_dnsmasqConfigUsesCtrld(t *testing.T) {
	good := func(server string) string {
		return strings.Join([]string{
			"no-resolv",
			server,
			"add-mac",
			"add-subnet=32,128",
			"cache-size=0",
			"",
		}, "\n")
	}

	tests := []struct {
		name    string
		ip      string
		port    int
		content string
		want    bool
	}{
		{
			name:    "wildcard listener maps to loopback",
			ip:      "0.0.0.0",
			port:    5354,
			content: good("server=127.0.0.1#5354"),
			want:    true,
		},
		{
			name:    "explicit listener",
			ip:      "127.0.0.2",
			port:    5355,
			content: good("server=127.0.0.2#5355"),
			want:    true,
		},
		{
			name:    "wrong upstream",
			ip:      "0.0.0.0",
			port:    5354,
			content: good("server=1.1.1.1#53"),
			want:    false,
		},
		{
			name: "additional server bypass",
			ip:   "0.0.0.0",
			port: 5354,
			content: good("server=127.0.0.1#5354") +
				"server=1.1.1.1#53\n",
			want: false,
		},
		{
			name: "servers file bypass",
			ip:   "0.0.0.0",
			port: 5354,
			content: good("server=127.0.0.1#5354") +
				"servers-file=/tmp/resolv.dnsmasq\n",
			want: false,
		},
		{
			name: "resolv file bypass",
			ip:   "0.0.0.0",
			port: 5354,
			content: good("server=127.0.0.1#5354") +
				"resolv-file=/tmp/resolv.conf\n",
			want: false,
		},
		{
			name:    "missing metadata directives",
			ip:      "0.0.0.0",
			port:    5354,
			content: "no-resolv\nserver=127.0.0.1#5354\ncache-size=0\n",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dnsmasq.conf")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			m := New(&ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{
				"0": {IP: tc.ip, Port: tc.port},
			}})
			got, err := m.dnsmasqConfigUsesCtrld(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("dnsmasqConfigUsesCtrld() = %v, want %v", got, tc.want)
			}
		})
	}
}

func Test_legacyCleanupJournalRoundTrip(t *testing.T) {
	entries := []legacySnapshotEntry{
		{state: legacyEntryPending, path: dnsmasq.MerlinJffsConfPath, hash: merlinSnapshotHash([]byte("main"))},
		{state: legacyEntryDelete, path: filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-1.conf"), hash: merlinSnapshotHash([]byte("sdn1"))},
		{state: legacyEntryRestore, path: filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-3.conf"), hash: merlinSnapshotHash([]byte("sdn3"))},
	}
	want := legacyCleanupJournal{phase: legacyCleanupPhase, entries: entries}
	buf, err := encodeLegacyCleanupJournal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseLegacyCleanupJournal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.phase != want.phase || len(got.entries) != len(want.entries) {
		t.Fatalf("journal mismatch: want %#v, got %#v", want, got)
	}
	for i := range want.entries {
		if got.entries[i] != want.entries[i] {
			t.Fatalf("entry %d mismatch: want %#v, got %#v", i, want.entries[i], got.entries[i])
		}
	}
}

func Test_parseLegacyCleanupJournalRejectsUnsafePath(t *testing.T) {
	hash := merlinSnapshotHash([]byte("x"))
	buf := []byte(legacyCleanupPhase + "\n" + legacyEntryPending + "\t/jffs/configs/profile.add\t" + hash + "\n")
	if _, err := parseLegacyCleanupJournal(buf); err == nil {
		t.Fatal("expected unsafe legacy snapshot path to be rejected")
	}
}

func Test_parseLegacyCleanupJournalFinalizeHasNoEntries(t *testing.T) {
	if _, err := parseLegacyCleanupJournal([]byte(legacyFinalizePhase + "\n")); err != nil {
		t.Fatalf("valid finalize journal rejected: %v", err)
	}
	hash := merlinSnapshotHash([]byte("x"))
	buf := []byte(legacyFinalizePhase + "\n" + legacyEntryPending + "\t" + dnsmasq.MerlinJffsConfPath + "\t" + hash + "\n")
	if _, err := parseLegacyCleanupJournal(buf); err == nil {
		t.Fatal("expected finalize journal with entries to be rejected")
	}
}

func Test_parseLegacyCleanupJournalRejectsUnknownEntryState(t *testing.T) {
	hash := merlinSnapshotHash([]byte("x"))
	buf := []byte(legacyCleanupPhase + "\nsurprise\t" + dnsmasq.MerlinJffsConfPath + "\t" + hash + "\n")
	if _, err := parseLegacyCleanupJournal(buf); err == nil {
		t.Fatal("expected unknown legacy entry state to be rejected")
	}
}

func Test_isLegacySnapshotPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{dnsmasq.MerlinJffsConfPath, true},
		{filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-1.conf"), true},
		{filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-123.conf"), true},
		{filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq.conf.add"), false},
		{filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-sdn.conf"), false},
		{"/tmp/dnsmasq-1.conf", false},
	}
	for _, tc := range tests {
		if got := isLegacySnapshotPath(tc.path); got != tc.want {
			t.Fatalf("isLegacySnapshotPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
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



func Test_mainSnapshotStateRoundTrip(t *testing.T) {
	want := mainSnapshotState{
		phase: snapshotPhaseQuarantine,
		hash:  merlinSnapshotHash([]byte("owned snapshot")),
	}
	buf, err := encodeMainSnapshotState(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseMainSnapshotState(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("snapshot state mismatch: want %#v, got %#v", want, got)
	}
}

func Test_parseMainSnapshotStateRejectsHashOnlyOwnership(t *testing.T) {
	buf := []byte("sha256=" + merlinSnapshotHash([]byte("legacy")) + "\n")
	if _, err := parseMainSnapshotState(buf); err == nil {
		t.Fatal("expected hash-only ownership state to be rejected")
	}
}

func Test_parseMainSnapshotStateRejectsUnknownPhase(t *testing.T) {
	buf := []byte(
		"snapshot-v2\nphase=surprise\nsha256=" +
			merlinSnapshotHash([]byte("owned")) + "\n",
	)
	if _, err := parseMainSnapshotState(buf); err == nil {
		t.Fatal("expected unknown snapshot phase to be rejected")
	}
}

func Test_sameFilePathsDistinguishesHardLinkFromIdenticalCopy(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	hardLink := filepath.Join(dir, "hard-link")
	copyPath := filepath.Join(dir, "copy")
	content := []byte("same bytes\n")

	if err := os.WriteFile(original, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, hardLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	same, err := sameFilePaths(original, hardLink)
	if err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Fatal("hard link to same inode was not recognized")
	}
	same, err = sameFilePaths(original, copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Fatal("byte-identical copy must not be treated as the owned inode")
	}
}

func Test_encodeMainSnapshotStateAcceptsEveryTransactionPhase(t *testing.T) {
	hash := merlinSnapshotHash([]byte("owned"))
	for _, phase := range []string{
		snapshotPhasePending,
		snapshotPhasePublished,
		snapshotPhaseQuarantine,
		snapshotPhaseDelete,
		snapshotPhaseRestore,
		snapshotPhaseRestored,
	} {
		if _, err := encodeMainSnapshotState(mainSnapshotState{phase: phase, hash: hash}); err != nil {
			t.Fatalf("phase %q rejected: %v", phase, err)
		}
	}
}


func Test_snapshotFileStillOwnedDetectsLateInodeModification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quarantine")
	anchor := filepath.Join(dir, "anchor")
	original := []byte("ctrld-owned\n")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, anchor); err != nil {
		t.Fatal(err)
	}
	expected := merlinSnapshotHash(original)

	owned, err := snapshotFileStillOwned(path, anchor, expected)
	if err != nil {
		t.Fatal(err)
	}
	if !owned {
		t.Fatal("unchanged hard-linked snapshot should be recognized as owned")
	}

	// Simulate a process which kept the inode open across quarantine and wrote
	// new contents before final deletion.
	if err := os.WriteFile(path, []byte("modified-through-same-inode\n"), 0644); err != nil {
		t.Fatal(err)
	}
	owned, err = snapshotFileStillOwned(path, anchor, expected)
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Fatal("late modification of the same inode must invalidate ownership for deletion")
	}
}

func Test_removeFileDurableAllowsRetryAfterFileAlreadyGone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "already-gone")
	if err := removeFileDurable(path); err != nil {
		t.Fatalf("durability retry for absent file failed: %v", err)
	}
}


func Test_merlinPostConfValidatesCtrldPidOwnership(t *testing.T) {
	for _, want := range []string{
		`case "$pid" in`,
		`[ -r "/proc/${pid}/cmdline" ]`,
		`tr '\000' '\n'`,
		`ctrld|*/ctrld)`,
		`ctrld_running=1`,
		`if [ "$ctrld_running" -eq 1 ]; then`,
	} {
		if !strings.Contains(dnsmasq.MerlinPostConfTmpl, want) {
			t.Fatalf("Merlin postconf is missing ctrld PID ownership check %q", want)
		}
	}
	if strings.Contains(dnsmasq.MerlinPostConfTmpl, `[ -f "/proc/${pid}/cmdline" ]; then`) {
		t.Fatal("Merlin postconf must not treat PID existence alone as ctrld ownership")
	}
}

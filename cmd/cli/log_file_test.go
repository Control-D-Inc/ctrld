package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const rotatingFileTestLineSize = 1024

// rotatingFileTestLine returns a line of a fixed size that names its
// generation, so a test can tell the content of one file from another.
func rotatingFileTestLine(generation, seq int) []byte {
	head := fmt.Sprintf("gen=%d seq=%d ", generation, seq)
	return []byte(head + strings.Repeat("x", rotatingFileTestLineSize-len(head)-1) + "\n")
}

func newTestRotatingFile(t *testing.T, budget logBudget) *rotatingFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ctrld.log")
	rf, err := newRotatingFile(path, budget, nil)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rf.close() })
	return rf
}

func rotatingFileTestContent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func writeRotatingFileTestLine(t *testing.T, rf *rotatingFile, generation, seq int) *logRotation {
	t.Helper()
	line := rotatingFileTestLine(generation, seq)
	n, rotated, err := rf.writeReporting(line)
	if err != nil {
		t.Fatalf("write gen=%d seq=%d: %v", generation, seq, err)
	}
	if n != len(line) {
		t.Fatalf("write gen=%d seq=%d wrote %d bytes, want %d", generation, seq, n, len(line))
	}
	return rotated
}

func Test_rotatingFileKeepsNumberedBackups(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 4096, backups: 4})
	rotations := 0
	for generation := 1; generation <= 7; generation++ {
		for seq := 1; seq <= 4; seq++ {
			if writeRotatingFileTestLine(t, rf, generation, seq) != nil {
				rotations++
			}
		}
	}
	if rotations != 6 {
		t.Fatalf("rotations = %d, want 6", rotations)
	}

	generationOf := map[string]int{"": 7, ".1": 6, ".2": 5, ".3": 4, ".4": 3}
	for suffix, generation := range generationOf {
		content := rotatingFileTestContent(t, rf.path+suffix)
		if want := fmt.Sprintf("gen=%d seq=1 ", generation); !strings.HasPrefix(content, want) {
			t.Fatalf("file %q starts with %.16q, want %q", rf.path+suffix, content, want)
		}
		if newer := fmt.Sprintf("gen=%d ", generation+1); strings.Contains(content, newer) {
			t.Fatalf("file %q holds %q", rf.path+suffix, newer)
		}
	}
	if _, err := os.Stat(rf.path + ".5"); !os.IsNotExist(err) {
		t.Fatalf("stat %s.5 = %v, want a not exist error", rf.path, err)
	}
}

func Test_rotatingFileHeaderStartsEveryFile(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 4096, backups: 1})
	header := []byte(`{"level":"info","journal":true,"message":"Log header"}` + "\n")
	rf.setHeader(header)
	if err := rf.writeHeader(); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	if rf.size != int64(len(header)) {
		t.Fatalf("size = %d, want %d", rf.size, len(header))
	}
	if got := strings.Count(rotatingFileTestContent(t, rf.path), string(header)); got != 1 {
		t.Fatalf("header count in the first file = %d, want 1", got)
	}

	rotations := 0
	for seq := 1; seq <= 5; seq++ {
		if writeRotatingFileTestLine(t, rf, 1, seq) != nil {
			rotations++
		}
	}
	if rotations != 1 {
		t.Fatalf("rotations = %d, want 1", rotations)
	}
	if !strings.HasPrefix(rotatingFileTestContent(t, rf.path+".1"), string(header)) {
		t.Fatal("the backup file does not start with the header")
	}
	content := rotatingFileTestContent(t, rf.path)
	if !strings.HasPrefix(content, string(header)) {
		t.Fatal("the new file does not start with the header")
	}
	if got := strings.Count(content, string(header)); got != 1 {
		t.Fatalf("header count in the new file = %d, want 1", got)
	}
	if want := int64(len(header) + 2*rotatingFileTestLineSize); rf.size != want {
		t.Fatalf("size = %d, want %d", rf.size, want)
	}
}

func Test_rotatingFileRotationRecord(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 4096, backups: 2})
	if rf.currentPath() != rf.path {
		t.Fatalf("currentPath = %q, want %q", rf.currentPath(), rf.path)
	}
	start := time.Now()
	for seq := 1; seq <= 3; seq++ {
		writeRotatingFileTestLine(t, rf, 1, seq)
	}
	sizeBeforeRotation := rf.size

	record, err := rf.rotateNow()
	if err != nil {
		t.Fatalf("rotateNow: %v", err)
	}
	if record == nil {
		t.Fatal("rotateNow returned no record")
	}
	if want := rf.path + ".1"; record.file != want {
		t.Fatalf("record.file = %q, want %q", record.file, want)
	}
	if record.backups != 2 {
		t.Fatalf("record.backups = %d, want 2", record.backups)
	}
	if record.bytesWritten != sizeBeforeRotation {
		t.Fatalf("record.bytesWritten = %d, want %d", record.bytesWritten, sizeBeforeRotation)
	}
	st, err := os.Stat(record.file)
	if err != nil {
		t.Fatalf("stat %s: %v", record.file, err)
	}
	if st.Size() != record.bytesWritten {
		t.Fatalf("%s holds %d bytes, record.bytesWritten = %d", record.file, st.Size(), record.bytesWritten)
	}
	if record.firstWrite.Before(start) {
		t.Fatalf("record.firstWrite = %v, want at or after %v", record.firstWrite, start)
	}
	if record.lastWrite.Before(record.firstWrite) {
		t.Fatalf("record.lastWrite = %v is before record.firstWrite = %v", record.lastWrite, record.firstWrite)
	}

	want := []string{rf.path + ".1", rf.path}
	if got := rf.paths(); !slices.Equal(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	writeRotatingFileTestLine(t, rf, 2, 1)
	if _, err := rf.rotateNow(); err != nil {
		t.Fatalf("second rotateNow: %v", err)
	}
	want = []string{rf.path + ".2", rf.path + ".1", rf.path}
	if got := rf.paths(); !slices.Equal(got, want) {
		t.Fatalf("paths after two rotations = %v, want %v", got, want)
	}
}

func Test_rotatingFileZeroBackupsTruncatesInPlace(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 2048, backups: 0})
	var record *logRotation
	for seq := 1; seq <= 3; seq++ {
		if rotated := writeRotatingFileTestLine(t, rf, 1, seq); rotated != nil {
			record = rotated
		}
	}
	if record == nil {
		t.Fatal("no rotation happened")
	}
	if record.file != rf.path {
		t.Fatalf("record.file = %q, want %q", record.file, rf.path)
	}
	if record.backups != 0 {
		t.Fatalf("record.backups = %d, want 0", record.backups)
	}
	if want := int64(2 * rotatingFileTestLineSize); record.bytesWritten != want {
		t.Fatalf("record.bytesWritten = %d, want %d", record.bytesWritten, want)
	}
	if _, err := os.Stat(rf.path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("stat %s.1 = %v, want a not exist error", rf.path, err)
	}
	if content := rotatingFileTestContent(t, rf.path); strings.Contains(content, "seq=1 ") {
		t.Fatal("the truncated file still holds the old content")
	}
	if got, want := rf.paths(), []string{rf.path}; !slices.Equal(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func Test_rotatingFileWriteCallsOnRotate(t *testing.T) {
	t.Run("one call per rotation", func(t *testing.T) {
		rf := newTestRotatingFile(t, logBudget{maxSize: 4096, backups: 4})
		var rotations atomic.Int64
		rf.onRotate = func(logRotation) { rotations.Add(1) }
		for generation := 1; generation <= 7; generation++ {
			for seq := 1; seq <= 4; seq++ {
				if _, err := rf.Write(rotatingFileTestLine(generation, seq)); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
		}
		if got := rotations.Load(); got != 6 {
			t.Fatalf("onRotate calls = %d, want 6", got)
		}
	})

	t.Run("reentrant callback does not deadlock", func(t *testing.T) {
		rf := newTestRotatingFile(t, logBudget{maxSize: 4096, backups: 1})
		const reentrantLine = "written from onRotate\n"
		var rotations atomic.Int64
		rf.onRotate = func(logRotation) {
			rotations.Add(1)
			if _, err := rf.Write([]byte(reentrantLine)); err != nil {
				t.Errorf("reentrant Write: %v", err)
			}
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for seq := 1; seq <= 5; seq++ {
				if _, err := rf.Write(rotatingFileTestLine(1, seq)); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Write did not return, a reentrant onRotate deadlocks it")
		}
		if got := rotations.Load(); got != 1 {
			t.Fatalf("onRotate calls = %d, want 1", got)
		}
		if !strings.Contains(rotatingFileTestContent(t, rf.path), reentrantLine) {
			t.Fatal("the new file does not hold the reentrant line")
		}
	})
}

func Test_rotatingFileCountsExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "ctrld.log")
	budget := logBudget{maxSize: 8192, backups: 1}
	rf, err := newRotatingFile(path, budget, nil)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	for seq := 1; seq <= 3; seq++ {
		writeRotatingFileTestLine(t, rf, 1, seq)
	}
	if err := rf.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := newRotatingFile(path, budget, nil)
	if err != nil {
		t.Fatalf("newRotatingFile on an existing file: %v", err)
	}
	t.Cleanup(func() { _ = reopened.close() })
	if want := int64(3 * rotatingFileTestLineSize); reopened.size != want {
		t.Fatalf("size = %d, want %d", reopened.size, want)
	}
	record, err := reopened.rotateNow()
	if err != nil {
		t.Fatalf("rotateNow: %v", err)
	}
	if want := int64(3 * rotatingFileTestLineSize); record.bytesWritten != want {
		t.Fatalf("record.bytesWritten = %d, want %d", record.bytesWritten, want)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if st.Size() != 0 {
		t.Fatalf("the new file holds %d bytes, want 0", st.Size())
	}
}

func Test_rotatingFileKeepsReopenError(t *testing.T) {
	reopenErr := errors.New("reopen refused")
	var opens atomic.Int64
	open := func(path string, flags int) (*os.File, error) {
		if opens.Add(1) > 1 {
			return nil, reopenErr
		}
		return os.OpenFile(path, flags, 0600)
	}
	path := filepath.Join(t.TempDir(), "ctrld.log")
	rf, err := newRotatingFile(path, logBudget{maxSize: 1024, backups: 1}, open)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rf.close() })

	writeRotatingFileTestLine(t, rf, 1, 1)
	if _, _, err := rf.writeReporting(rotatingFileTestLine(1, 2)); !errors.Is(err, reopenErr) {
		t.Fatalf("write after a failed reopen = %v, want %v", err, reopenErr)
	}
	if rf.f != nil {
		t.Fatal("the file is still open after a failed reopen")
	}
	if _, _, err := rf.writeReporting(rotatingFileTestLine(1, 3)); !errors.Is(err, reopenErr) {
		t.Fatalf("later write = %v, want %v", err, reopenErr)
	}

	oversized := make([]byte, 2*rotatingFileTestLineSize)
	_, rotated, err := rf.writeReporting(oversized)
	if !errors.Is(err, reopenErr) {
		t.Fatalf("oversized write = %v, want %v", err, reopenErr)
	}
	if rotated != nil {
		t.Fatalf("a closed file reported a rotation of %q", rotated.file)
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Fatalf("stat %s.2 = %v, want a not exist error: a closed file shifted the backups", path, err)
	}
}

func Test_rotatingFileRetriesAFailedOpen(t *testing.T) {
	origInterval := retryOpenInterval
	retryOpenInterval = 10 * time.Millisecond
	t.Cleanup(func() { retryOpenInterval = origInterval })

	openErr := errors.New("open refused")
	opens := 0
	open := func(path string, flags int) (*os.File, error) {
		opens++
		if opens == 2 {
			return nil, openErr
		}
		return os.OpenFile(path, flags, 0600)
	}
	path := filepath.Join(t.TempDir(), "ctrld.log")
	rf, err := newRotatingFile(path, logBudget{maxSize: rotatingFileTestLineSize, backups: 1}, open)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rf.close() })
	header := []byte(`{"level":"info","journal":true,"message":"Log header"}` + "\n")
	rf.setHeader(header)

	writeRotatingFileTestLine(t, rf, 1, 1)
	if _, _, err := rf.writeReporting(rotatingFileTestLine(1, 2)); !errors.Is(err, openErr) {
		t.Fatalf("write after a failed reopen = %v, want %v", err, openErr)
	}
	if _, _, err := rf.writeReporting(rotatingFileTestLine(1, 3)); !errors.Is(err, openErr) {
		t.Fatalf("write inside the retry interval = %v, want %v", err, openErr)
	}
	if opens != 2 {
		t.Fatalf("opens = %d, want 2: a write inside the retry interval opened the file again", opens)
	}

	time.Sleep(2 * retryOpenInterval)
	writeRotatingFileTestLine(t, rf, 1, 4)

	content := rotatingFileTestContent(t, path)
	if !strings.HasPrefix(content, string(header)) {
		t.Fatalf("the reopened file starts with %.40q, want the header", content)
	}
	if !strings.Contains(content, "gen=1 seq=4 ") {
		t.Fatalf("the reopened file misses the line that followed the retry: %.80q", content)
	}
}

func Test_pruneNumberedBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, logFileName)
	numbered := []string{path + ".1", path + ".2", path + ".3", path + ".4"}
	// A prune must keep every file that another writer owns, because log_path
	// can name a file in a directory full of them.
	foreign := []string{path + ".bak", filepath.Join(dir, journalLogFileName+".3"), filepath.Join(dir, "syslog.5")}
	for _, name := range append(slices.Clone(numbered), foreign...) {
		if err := os.WriteFile(name, []byte("old\n"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	pruneNumberedBackups(path, 1)

	if _, err := os.Stat(numbered[0]); err != nil {
		t.Fatalf("the backup inside the count went away: %v", err)
	}
	for _, name := range numbered[1:] {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after a prune that keeps one backup (err %v)", name, err)
		}
	}
	for _, name := range foreign {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("the prune removed %s, which it does not own: %v", name, err)
		}
	}
}

func Test_rotatingFileKeepsFilesAboveTheCount(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 2 * rotatingFileTestLineSize, backups: 1})
	late := rf.backupPath(3)
	if err := os.WriteFile(late, []byte("late\n"), 0600); err != nil {
		t.Fatalf("write the late backup: %v", err)
	}

	for seq := 1; seq <= 3; seq++ {
		if _, err := rf.Write(rotatingFileTestLine(1, seq)); err != nil {
			t.Fatalf("write %d: %v", seq, err)
		}
	}

	if _, err := os.Stat(late); err != nil {
		t.Fatalf("a rotation removed %s, which sits above the backup count: %v", late, err)
	}
	if _, err := os.Stat(rf.backupPath(1)); err != nil {
		t.Fatalf("the rotation left no .1 file: %v", err)
	}
}

func Test_rotatingFileDoesNotFollowASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows opener takes no symlink flag")
	}
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.log")
	if err := os.WriteFile(planted, []byte("planted\n"), 0600); err != nil {
		t.Fatalf("write the planted file: %v", err)
	}
	path := filepath.Join(dir, "ctrld.log")
	if err := os.Symlink(planted, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	rf, err := newRotatingFile(path, logBudget{maxSize: 4096, backups: 1}, nil)

	if err == nil {
		_ = rf.close()
		t.Fatal("newRotatingFile followed the symlink")
	}
	if got := rotatingFileTestContent(t, planted); got != "planted\n" {
		t.Fatalf("the planted file = %q, want it untouched", got)
	}
}

func Test_rotatingFileKeepsContentWhenRenameFails(t *testing.T) {
	renameErr := errors.New("rename refused")
	renameFails := true
	path := filepath.Join(t.TempDir(), "ctrld.log")
	rf, err := newRotatingFile(path, logBudget{maxSize: 2 * rotatingFileTestLineSize, backups: 1}, nil)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	t.Cleanup(func() { _ = rf.close() })
	rf.rename = func(oldpath, newpath string) error {
		if renameFails {
			return renameErr
		}
		return os.Rename(oldpath, newpath)
	}

	for seq := 1; seq <= 2; seq++ {
		writeRotatingFileTestLine(t, rf, 1, seq)
	}
	record := writeRotatingFileTestLine(t, rf, 1, 3)
	if record == nil {
		t.Fatal("the write past the budget reported no rotation")
	}
	if !errors.Is(record.err, renameErr) {
		t.Fatalf("record.err = %v, want %v", record.err, renameErr)
	}
	content := rotatingFileTestContent(t, path)
	for seq := 1; seq <= 3; seq++ {
		if want := fmt.Sprintf("gen=1 seq=%d ", seq); !strings.Contains(content, want) {
			t.Fatalf("the file lost %q after a failed rename", want)
		}
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("stat %s.1 = %v, want a not exist error", path, err)
	}
	if writeRotatingFileTestLine(t, rf, 1, 4) != nil {
		t.Fatal("the next write rotated again instead of waiting for another budget")
	}

	renameFails = false
	var second *logRotation
	for seq := 5; seq <= 6; seq++ {
		if rotated := writeRotatingFileTestLine(t, rf, 1, seq); rotated != nil {
			second = rotated
		}
	}
	if second == nil {
		t.Fatal("no rotation happened after the rename worked again")
	}
	if second.err != nil {
		t.Fatalf("record.err = %v, want no error", second.err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("stat %s.1 after a working rename: %v", path, err)
	}
}

// Test_zeroBackupRotationKeepsTheOpenReader opens an upload reader over the
// current file, then rotates with no backup. The reader must return the bytes
// and the size that it advertised, and the current file holds the new
// generation only.
func Test_zeroBackupRotationKeepsTheOpenReader(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 1 << 20, backups: 0})
	if _, err := rf.Write([]byte("old generation!\n")); err != nil {
		t.Fatal(err)
	}
	var upload logParts
	upload.addBoundedFiles(rf.paths(), 0)
	t.Cleanup(upload.close)

	if _, err := rf.rotateNow(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := rf.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(io.MultiReader(upload.readers...))
	if err != nil {
		t.Fatal(err)
	}
	if upload.size != 16 || string(got) != "old generation!\n" {
		t.Fatalf("reader gave %q (%d bytes advertised), want the old generation of 16 bytes", got, upload.size)
	}
	if content := rotatingFileTestContent(t, rf.currentPath()); content != "new\n" {
		t.Fatalf("current file = %q, want the new generation only", content)
	}
	if _, err := os.Stat(rf.currentPath() + rotatingSuffix); !os.IsNotExist(err) {
		t.Fatalf("the moved file is still on disk: %v", err)
	}
}

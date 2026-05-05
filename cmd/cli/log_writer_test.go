package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func Test_logWriter_Write(t *testing.T) {
	size := 64 * 1024
	lw := &logWriter{size: size}
	lw.buf.Grow(lw.size)
	data := strings.Repeat("A", size)
	lw.Write([]byte(data))
	if lw.buf.String() != data {
		t.Fatalf("unexpected buf content: %v", lw.buf.String())
	}
	newData := "B"
	halfData := strings.Repeat("A", len(data)/2) + logWriterInitEndMarker
	lw.Write([]byte(newData))
	if lw.buf.String() != halfData+newData {
		t.Fatalf("unexpected new buf content: %v", lw.buf.String())
	}

	bigData := strings.Repeat("B", 256*1024)
	expected := halfData + strings.Repeat("B", 16*1024)
	lw.Write([]byte(bigData))
	if lw.buf.String() != expected {
		t.Fatalf("unexpected big buf content: %v", lw.buf.String())
	}
}

func Test_logWriter_ConcurrentWrite(t *testing.T) {
	size := 64 * 1024
	lw := &logWriter{size: size}
	n := 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			lw.Write([]byte(strings.Repeat("A", i)))
		}()
	}
	wg.Wait()
	if lw.buf.Len() > lw.size {
		t.Fatalf("unexpected buf size: %v, content: %q", lw.buf.Len(), lw.buf.String())
	}
}

func Test_logWriter_MarkerInitEnd(t *testing.T) {
	size := 64 * 1024
	lw := &logWriter{size: size}
	lw.buf.Grow(lw.size)

	paddingSize := 10
	// Writing half of the size, minus len(end marker) and padding size.
	dataSize := size/2 - len(logWriterInitEndMarker) - paddingSize
	data := strings.Repeat("A", dataSize)
	// Inserting newline for making partial init data
	data += "\n"
	// Filling left over buffer to make the log full.
	// The data length: len(end marker) + padding size - 1 (for newline above) + size/2
	data += strings.Repeat("A", len(logWriterInitEndMarker)+paddingSize-1+(size/2))
	lw.Write([]byte(data))
	if lw.buf.String() != data {
		t.Fatalf("unexpected buf content: %v", lw.buf.String())
	}
	lw.Write([]byte("B"))
	lw.Write([]byte(strings.Repeat("B", 256*1024)))
	firstIdx := strings.Index(lw.buf.String(), logWriterInitEndMarker)
	lastIdx := strings.LastIndex(lw.buf.String(), logWriterInitEndMarker)
	// Check if init end marker present.
	if firstIdx == -1 || lastIdx == -1 {
		t.Fatalf("missing init end marker: %s", lw.buf.String())
	}
	// Check if init end marker appears only once.
	if firstIdx != lastIdx {
		t.Fatalf("log init end marker appears more than once: %s", lw.buf.String())
	}
	// Ensure that we have the correct init log data.
	if !strings.Contains(lw.buf.String(), strings.Repeat("A", dataSize)+logWriterInitEndMarker) {
		t.Fatalf("unexpected log content: %s", lw.buf.String())
	}
}

func Test_logWriter_SetLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	lw := newLogWriterWithSize(logWriterSize)
	if err := lw.setLogFile(path); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	defer lw.closeLogFile()

	msg := "hello file\n"
	lw.Write([]byte(msg))

	// Verify data in memory buffer.
	if lw.buf.String() != msg {
		t.Fatalf("buffer: got %q, want %q", lw.buf.String(), msg)
	}
	// Verify data on disk.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != msg {
		t.Fatalf("file: got %q, want %q", data, msg)
	}
}

func Test_logWriter_FileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	// Use a tiny max size to trigger rotation quickly.
	lw := newLogWriterWithSize(logWriterSize)
	if err := lw.setLogFile(path); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	defer lw.closeLogFile()

	// Write enough to exceed logFileMaxSize.
	chunk := strings.Repeat("X", 1024) + "\n"
	written := 0
	for written < logFileMaxSize+1024 {
		lw.Write([]byte(chunk))
		written += len(chunk)
	}

	// Backup file should exist.
	backupPath := path + ".1"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Fatal("expected backup file to exist after rotation")
	}

	// Current file should be smaller than max (it was rotated).
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	if st.Size() > logFileMaxSize {
		t.Fatalf("current file too large after rotation: %d", st.Size())
	}
}

func Test_logWriter_FilePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	lw := newLogWriterWithSize(logWriterSize)

	// No file configured.
	c, b := lw.logFilePaths()
	if c != "" || b != "" {
		t.Fatalf("expected empty paths, got %q %q", c, b)
	}

	if err := lw.setLogFile(path); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	defer lw.closeLogFile()

	// Current exists, no backup yet.
	c, b = lw.logFilePaths()
	if c != path {
		t.Fatalf("current: got %q, want %q", c, path)
	}
	if b != "" {
		t.Fatalf("backup should be empty, got %q", b)
	}

	// Create a backup file manually.
	os.WriteFile(path+".1", []byte("old"), 0600)
	_, b = lw.logFilePaths()
	if b != path+".1" {
		t.Fatalf("backup: got %q, want %q", b, path+".1")
	}
}

func Test_logWriter_FileAppendOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Simulate first run.
	lw1 := newLogWriterWithSize(logWriterSize)
	if err := lw1.setLogFile(path); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	lw1.Write([]byte("run1\n"))
	lw1.closeLogFile()

	// Simulate second run (restart) — file should be appended.
	lw2 := newLogWriterWithSize(logWriterSize)
	if err := lw2.setLogFile(path); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	lw2.Write([]byte("run2\n"))
	lw2.closeLogFile()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := "run1\nrun2\n"
	if string(data) != want {
		t.Fatalf("file: got %q, want %q", data, want)
	}
}

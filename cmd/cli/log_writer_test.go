package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
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

// testLogWriterBudget keeps the rotation tests small: four lines fill the
// current file.
var testLogWriterBudget = logBudget{maxSize: 4 * rotatingFileTestLineSize, backups: 2}

func newTestFileLogWriter(t *testing.T, budget logBudget) (*logWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.log")
	lw := newLogWriterWithSize(logWriterSize)
	if err := lw.setLogFile(path, budget); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	t.Cleanup(lw.closeLogFile)
	return lw, path
}

func Test_logWriter_SetLogFile(t *testing.T) {
	lw, path := newTestFileLogWriter(t, testLogWriterBudget)

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
	lw, path := newTestFileLogWriter(t, testLogWriterBudget)

	// Three rotations: each file takes four lines.
	for seq := 1; seq <= 16; seq++ {
		lw.Write(rotatingFileTestLine(1, seq))
	}

	for _, suffix := range []string{".1", ".2"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Fatalf("stat %s: %v", path+suffix, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("stat %s.3 = %v, want a not exist error", path, err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	if want := testLogWriterBudget.maxSize + rotatingFileTestLineSize; st.Size() > want {
		t.Fatalf("current file holds %d bytes after rotation, want at most %d", st.Size(), want)
	}
}

func Test_logWriter_RotatingPaths(t *testing.T) {
	lw := newLogWriterWithSize(logWriterSize)
	if lw.rotating() != nil {
		t.Fatal("a writer without a file has a rotating file, want none")
	}

	lw, path := newTestFileLogWriter(t, testLogWriterBudget)
	if got, want := lw.rotating().paths(), []string{path}; !slices.Equal(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}

	// Two rotations, so both backups exist.
	for seq := 1; seq <= 9; seq++ {
		lw.Write(rotatingFileTestLine(1, seq))
	}
	want := []string{path + ".2", path + ".1", path}
	if got := lw.rotating().paths(); !slices.Equal(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func Test_logWriter_FileAppendOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Simulate first run.
	lw1 := newLogWriterWithSize(logWriterSize)
	if err := lw1.setLogFile(path, testLogWriterBudget); err != nil {
		t.Fatalf("setLogFile: %v", err)
	}
	lw1.Write([]byte("run1\n"))
	lw1.closeLogFile()

	// Simulate second run (restart) — file should be appended.
	lw2 := newLogWriterWithSize(logWriterSize)
	if err := lw2.setLogFile(path, testLogWriterBudget); err != nil {
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

func Test_logWriter_EmitsLogRotated(t *testing.T) {
	setLogHeaderTestGlobalLevel(t, zerolog.DebugLevel)
	lw, path := newTestFileLogWriter(t, testLogWriterBudget)

	// The logger writes back into the writer that rotates, which is the case
	// that deadlocks when the writer still holds its lock.
	buf := &syncBuffer{}
	logger := zerolog.New(zerolog.MultiLevelWriter(lw, buf))
	old := mainLog.Load()
	mainLog.Store(&logger)
	t.Cleanup(func() { mainLog.Store(old) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for seq := 1; seq <= 5; seq++ {
			lw.Write(rotatingFileTestLine(1, seq))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the writer did not return: the rotation event blocked on the writer lock")
	}

	st, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("stat %s.1: %v", path, err)
	}

	var rotatedLines []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "Log rotated") {
			rotatedLines = append(rotatedLines, line)
		}
	}
	if len(rotatedLines) != 1 {
		t.Fatalf("got %d Log rotated events, want 1: %q", len(rotatedLines), buf.String())
	}
	if !strings.Contains(rotatedLines[0], string(journalMarker)) {
		t.Fatalf("the event is not marked for the journal: %s", rotatedLines[0])
	}
	var event struct {
		File         string `json:"file"`
		BytesWritten int64  `json:"bytes_written"`
	}
	if err := json.Unmarshal([]byte(rotatedLines[0]), &event); err != nil {
		t.Fatalf("unmarshal %s: %v", rotatedLines[0], err)
	}
	if event.File != path+".1" {
		t.Fatalf("file = %q, want %q", event.File, path+".1")
	}
	if event.BytesWritten != st.Size() {
		t.Fatalf("bytes_written = %d, want %d", event.BytesWritten, st.Size())
	}
}

func Test_logWriter_NestedRotationStillEmitsEvent(t *testing.T) {
	setLogHeaderTestGlobalLevel(t, zerolog.DebugLevel)
	debugLog, debugPath := newTestFileLogWriter(t, testLogWriterBudget)
	journalLog, journalPath := newTestFileLogWriter(t, logBudget{maxSize: 2 * rotatingFileTestLineSize, backups: 1})

	buf := &syncBuffer{}
	logger := zerolog.New(zerolog.MultiLevelWriter(debugLog, journalLog, buf))
	old := mainLog.Load()
	mainLog.Store(&logger)
	t.Cleanup(func() { mainLog.Store(old) })

	// Fill the journal, so the rotation event of the debug file is the line
	// that rotates the journal. That nested rotation needs its own event.
	journalLog.Write(rotatingFileTestLine(1, 1))
	journalLog.Write(rotatingFileTestLine(1, 2))
	for seq := 1; seq <= 5; seq++ {
		debugLog.Write(rotatingFileTestLine(1, seq))
	}

	rotatedFiles := map[string]bool{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, "Log rotated") {
			continue
		}
		var event struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		rotatedFiles[event.File] = true
	}
	for _, want := range []string{debugPath + ".1", journalPath + ".1"} {
		if !rotatedFiles[want] {
			t.Fatalf("no Log rotated event for %s; events: %v", want, rotatedFiles)
		}
	}
	if len(rotatedFiles) != 2 {
		t.Fatalf("got %d rotated files, want 2: %v", len(rotatedFiles), rotatedFiles)
	}
}

// rotationEventFields parses one log line into its raw fields, so a test can
// ask whether a field is there at all.
func rotationEventFields(t *testing.T, line string) map[string]json.RawMessage {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &fields); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	return fields
}

func Test_emitLogRotated_eventTimes(t *testing.T) {
	setLogHeaderTestGlobalLevel(t, zerolog.DebugLevel)

	t.Run("a file with no event names no time", func(t *testing.T) {
		buf := captureMainLog(t)

		emitLogRotated(logRotation{file: "/tmp/ctrld.log.1", backups: 1})

		fields := rotationEventFields(t, buf.String())
		for _, name := range []string{"first_event_at", "last_event_at"} {
			if raw, ok := fields[name]; ok {
				t.Errorf("%s = %s, want no field for a file with no event", name, raw)
			}
		}
	})

	t.Run("a file with events names both times", func(t *testing.T) {
		buf := captureMainLog(t)
		now := time.Now()

		emitLogRotated(logRotation{file: "/tmp/ctrld.log.1", backups: 1, firstWrite: now, lastWrite: now})

		fields := rotationEventFields(t, buf.String())
		for _, name := range []string{"first_event_at", "last_event_at"} {
			if _, ok := fields[name]; !ok {
				t.Errorf("%s is missing: %v", name, fields)
			}
		}
	})
}

func Test_emitLogRotated_reportsAFailedRotation(t *testing.T) {
	setLogHeaderTestGlobalLevel(t, zerolog.DebugLevel)
	buf := captureMainLog(t)

	emitLogRotated(logRotation{file: "/tmp/ctrld.log.1", err: errors.New("rename refused")})

	var event struct {
		Level   string `json:"level"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &event); err != nil {
		t.Fatalf("unmarshal %q: %v", buf.String(), err)
	}
	if event.Message != "Log rotation failed" {
		t.Errorf("message = %q, want %q", event.Message, "Log rotation failed")
	}
	if event.Level != "warn" {
		t.Errorf("level = %q, want %q", event.Level, "warn")
	}
	if event.Error != "rename refused" {
		t.Errorf("error = %q, want %q", event.Error, "rename refused")
	}
}

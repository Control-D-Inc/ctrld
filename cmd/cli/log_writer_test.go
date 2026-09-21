package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	lw, path := newTestFileLogWriter(t, testLogWriterBudget)

	// The logger writes back into the writer that rotates, which is the case
	// that deadlocks when the writer still holds its lock.
	buf := &syncBuffer{}
	logger := newTestJSONLogger(lw, buf)
	old := mainLog.Load()
	mainLog.Store(logger)
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
	debugLog, debugPath := newTestFileLogWriter(t, testLogWriterBudget)
	journalLog, journalPath := newTestFileLogWriter(t, logBudget{maxSize: 2 * rotatingFileTestLineSize, backups: 1})

	buf := &syncBuffer{}
	logger := newTestJSONLogger(debugLog, journalLog, buf)
	old := mainLog.Load()
	mainLog.Store(logger)
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

	t.Run("a file with no event names no time", func(t *testing.T) {
		buf := captureJSONMainLog(t)

		emitLogRotated(logRotation{file: "/tmp/ctrld.log.1", backups: 1})

		fields := rotationEventFields(t, buf.String())
		for _, name := range []string{"first_event_at", "last_event_at"} {
			if raw, ok := fields[name]; ok {
				t.Errorf("%s = %s, want no field for a file with no event", name, raw)
			}
		}
	})

	t.Run("a file with events names both times", func(t *testing.T) {
		buf := captureJSONMainLog(t)
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
	buf := captureJSONMainLog(t)

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

// TestNoticeLevel tests that the custom NOTICE level works correctly
func TestNoticeLevel(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create encoder config with custom NOTICE level support
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
	encoderConfig.EncodeLevel = noticeLevelEncoder

	// Test with NOTICE level
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), ctrld.NoticeLevel)
	logger := zap.New(core)
	ctrldLogger := &ctrld.Logger{Logger: logger}

	// Log messages at different levels
	ctrldLogger.Debug().Msg("This is a DEBUG message")
	ctrldLogger.Info().Msg("This is an INFO message")
	ctrldLogger.Notice().Msg("This is a NOTICE message")
	ctrldLogger.Warn().Msg("This is a WARN message")
	ctrldLogger.Error().Msg("This is an ERROR message")

	output := buf.String()

	// Verify that DEBUG and INFO messages are NOT logged (filtered out)
	if strings.Contains(output, "DEBUG") {
		t.Error("DEBUG message should not be logged when level is NOTICE")
	}
	if strings.Contains(output, "INFO") {
		t.Error("INFO message should not be logged when level is NOTICE")
	}

	// Verify that NOTICE, WARN, and ERROR messages ARE logged
	if !strings.Contains(output, "NOTICE") {
		t.Error("NOTICE message should be logged when level is NOTICE")
	}
	if !strings.Contains(output, "WARN") {
		t.Error("WARN message should be logged when level is NOTICE")
	}
	if !strings.Contains(output, "ERROR") {
		t.Error("ERROR message should be logged when level is NOTICE")
	}

	// Verify the NOTICE message content
	if !strings.Contains(output, "This is a NOTICE message") {
		t.Error("NOTICE message content should be present")
	}

	t.Logf("Log output with NOTICE level:\n%s", output)
}

func TestNewLogReader(t *testing.T) {
	tests := []struct {
		name        string
		bufContent  string
		stripColor  bool
		expected    string
		description string
	}{
		{
			name:        "empty_buffer_no_color_strip",
			bufContent:  "",
			stripColor:  false,
			expected:    "",
			description: "Empty buffer should return empty reader",
		},
		{
			name:        "empty_buffer_with_color_strip",
			bufContent:  "",
			stripColor:  true,
			expected:    "",
			description: "Empty buffer with color strip should return empty reader",
		},
		{
			name:        "plain_text_no_color_strip",
			bufContent:  "This is plain text without any color codes",
			stripColor:  false,
			expected:    "This is plain text without any color codes",
			description: "Plain text should be returned as-is when not stripping colors",
		},
		{
			name:        "plain_text_with_color_strip",
			bufContent:  "This is plain text without any color codes",
			stripColor:  true,
			expected:    "This is plain text without any color codes",
			description: "Plain text should be returned as-is when stripping colors",
		},
		{
			name:        "text_with_ansi_codes_no_strip",
			bufContent:  "Normal text \x1b[31mred text\x1b[0m normal again",
			stripColor:  false,
			expected:    "Normal text \x1b[31mred text\x1b[0m normal again",
			description: "ANSI color codes should be preserved when not stripping",
		},
		{
			name:        "text_with_ansi_codes_with_strip",
			bufContent:  "Normal text \x1b[31mred text\x1b[0m normal again",
			stripColor:  true,
			expected:    "Normal text red text normal again",
			description: "ANSI color codes should be removed when stripping colors",
		},
		{
			name:        "multiple_ansi_codes_no_strip",
			bufContent:  "\x1b[1mBold\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m text",
			stripColor:  false,
			expected:    "\x1b[1mBold\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m text",
			description: "Multiple ANSI codes should be preserved when not stripping",
		},
		{
			name:        "multiple_ansi_codes_with_strip",
			bufContent:  "\x1b[1mBold\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m text",
			stripColor:  true,
			expected:    "Bold Green Blue text",
			description: "Multiple ANSI codes should be removed when stripping colors",
		},
		{
			name:        "complex_ansi_sequences_no_strip",
			bufContent:  "\x1b[1;31;42mBold red on green\x1b[0m \x1b[38;5;208mOrange\x1b[0m",
			stripColor:  false,
			expected:    "\x1b[1;31;42mBold red on green\x1b[0m \x1b[38;5;208mOrange\x1b[0m",
			description: "Complex ANSI sequences should be preserved when not stripping",
		},
		{
			name:        "complex_ansi_sequences_with_strip",
			bufContent:  "\x1b[1;31;42mBold red on green\x1b[0m \x1b[38;5;208mOrange\x1b[0m",
			stripColor:  true,
			expected:    "Bold red on green Orange",
			description: "Complex ANSI sequences should be removed when stripping colors",
		},
		{
			name:        "ansi_codes_with_newlines_no_strip",
			bufContent:  "Line 1\n\x1b[31mRed line\x1b[0m\nLine 3",
			stripColor:  false,
			expected:    "Line 1\n\x1b[31mRed line\x1b[0m\nLine 3",
			description: "ANSI codes with newlines should be preserved when not stripping",
		},
		{
			name:        "ansi_codes_with_newlines_with_strip",
			bufContent:  "Line 1\n\x1b[31mRed line\x1b[0m\nLine 3",
			stripColor:  true,
			expected:    "Line 1\nRed line\nLine 3",
			description: "ANSI codes with newlines should be removed when stripping colors",
		},
		{
			name:        "malformed_ansi_codes_no_strip",
			bufContent:  "Text \x1b[invalidm \x1b[0m normal",
			stripColor:  false,
			expected:    "Text \x1b[invalidm \x1b[0m normal",
			description: "Malformed ANSI codes should be preserved when not stripping",
		},
		{
			name:        "malformed_ansi_codes_with_strip",
			bufContent:  "Text \x1b[invalidm \x1b[0m normal",
			stripColor:  true,
			expected:    "Text \x1b[invalidm  normal",
			description: "Non-matching ANSI sequences should be preserved when stripping colors",
		},
		{
			name:        "large_buffer_no_strip",
			bufContent:  strings.Repeat("A", 10000) + "\x1b[31m" + strings.Repeat("B", 1000) + "\x1b[0m",
			stripColor:  false,
			expected:    strings.Repeat("A", 10000) + "\x1b[31m" + strings.Repeat("B", 1000) + "\x1b[0m",
			description: "Large buffer should handle ANSI codes correctly when not stripping",
		},
		{
			name:        "large_buffer_with_strip",
			bufContent:  strings.Repeat("A", 10000) + "\x1b[31m" + strings.Repeat("B", 1000) + "\x1b[0m",
			stripColor:  true,
			expected:    strings.Repeat("A", 10000) + strings.Repeat("B", 1000),
			description: "Large buffer should remove ANSI codes correctly when stripping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a buffer with the test content
			buf := &bytes.Buffer{}
			buf.WriteString(tt.bufContent)

			// Create the log reader
			reader := newLogReader(buf, tt.stripColor)

			// Read all content from the reader
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("Failed to read from log reader: %v", err)
			}

			// Verify the content matches expected
			actual := string(content)
			if actual != tt.expected {
				t.Errorf("Expected content: %q, got: %q", tt.expected, actual)
				t.Logf("Description: %s", tt.description)
			}
		})
	}
}

func TestNewLogReader_ReaderBehavior(t *testing.T) {
	// Test that the returned reader behaves correctly
	buf := &bytes.Buffer{}
	buf.WriteString("Test content with \x1b[31mred\x1b[0m text")

	// Test with color stripping
	reader := newLogReader(buf, true)

	// Test reading in chunks
	chunk1 := make([]byte, 10)
	n1, err := reader.Read(chunk1)
	if err != nil && err != io.EOF {
		t.Fatalf("Unexpected error reading first chunk: %v", err)
	}
	if n1 != 10 {
		t.Errorf("Expected to read 10 bytes, got %d", n1)
	}

	// Test reading remaining content
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read remaining content: %v", err)
	}

	// Verify total content
	totalContent := string(chunk1[:n1]) + string(remaining)
	expected := "Test content with red text"
	if totalContent != expected {
		t.Errorf("Expected total content: %q, got: %q", expected, totalContent)
	}
}

func TestNewLogReader_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to the same buffer
	buf := &bytes.Buffer{}
	buf.WriteString("Concurrent test with \x1b[32mgreen\x1b[0m text")

	var wg sync.WaitGroup
	numGoroutines := 10
	results := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader := newLogReader(buf, true)
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("Failed to read content: %v", err)
				return
			}
			results <- string(content)
		}()
	}

	wg.Wait()
	close(results)

	// Verify all goroutines got the same result
	expected := "Concurrent test with green text"
	for result := range results {
		if result != expected {
			t.Errorf("Expected: %q, got: %q", expected, result)
		}
	}
}

func TestNewLogReader_ANSIRegexEdgeCases(t *testing.T) {
	// Test edge cases for ANSI regex matching
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty_escape_sequence",
			input:    "Text \x1b[m normal",
			expected: "Text  normal",
		},
		{
			name:     "multiple_semicolons",
			input:    "Text \x1b[1;2;3;4m normal",
			expected: "Text  normal",
		},
		{
			name:     "numeric_only",
			input:    "Text \x1b[123m normal",
			expected: "Text  normal",
		},
		{
			name:     "mixed_numeric_semicolon",
			input:    "Text \x1b[1;23;456m normal",
			expected: "Text  normal",
		},
		{
			name:     "no_closing_bracket",
			input:    "Text \x1b[31 normal",
			expected: "Text \x1b[31 normal",
		},
		{
			name:     "no_opening_bracket",
			input:    "Text 31m normal",
			expected: "Text 31m normal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			buf.WriteString(tt.input)

			reader := newLogReader(buf, true)
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("Failed to read content: %v", err)
			}

			actual := string(content)
			if actual != tt.expected {
				t.Errorf("Expected: %q, got: %q", tt.expected, actual)
			}
		})
	}
}

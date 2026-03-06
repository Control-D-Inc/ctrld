package cli

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
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

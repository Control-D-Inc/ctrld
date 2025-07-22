package cli

import (
	"bytes"
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

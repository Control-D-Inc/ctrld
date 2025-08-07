package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

// Log writer constants for buffer management and log formatting
const (
	// logWriterSize is the default buffer size for log writers
	// This provides sufficient space for runtime logs without excessive memory usage
	logWriterSize          = 1024 * 1024 * 5 // 5 MB

	// logWriterSmallSize is used for memory-constrained environments
	// This reduces memory footprint while still maintaining log functionality
	logWriterSmallSize     = 1024 * 1024 * 1 // 1 MB

	// logWriterInitialSize is the initial buffer allocation
	// This provides immediate space for early log entries
	logWriterInitialSize   = 32 * 1024       // 32 KB

	// logWriterSentInterval controls how often logs are sent to external systems
	// This balances real-time logging with system performance
	logWriterSentInterval  = time.Minute

	// logWriterInitEndMarker marks the end of initialization logs
	// This helps separate startup logs from runtime logs
	logWriterInitEndMarker = "\n\n=== INIT_END ===\n\n"

	// logWriterLogEndMarker marks the end of log sections
	// This provides clear boundaries for log parsing and analysis
	logWriterLogEndMarker  = "\n\n=== LOG_END ===\n\n"
)

// Custom level encoders that handle NOTICE level
// Since NOTICE and WARN share the same numeric value (1), we handle them specially
// in the encoder to display NOTICE messages with the "NOTICE" prefix.
// Note: WARN messages will also display as "NOTICE" because they share the same level value.
// This is the intended behavior for visual distinction.

// noticeLevelEncoder provides custom level encoding for NOTICE level
// This ensures NOTICE messages are clearly distinguished from other log levels
func noticeLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch l {
	case ctrld.NoticeLevel:
		enc.AppendString("NOTICE")
	default:
		zapcore.CapitalLevelEncoder(l, enc)
	}
}

// noticeColorLevelEncoder provides colored level encoding for NOTICE level
// This uses cyan color to make NOTICE messages visually distinct in terminal output
func noticeColorLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch l {
	case ctrld.NoticeLevel:
		enc.AppendString("\x1b[36mNOTICE\x1b[0m") // Cyan color for NOTICE
	default:
		zapcore.CapitalColorLevelEncoder(l, enc)
	}
}

// logViewResponse represents the response structure for log viewing requests
// This provides a consistent JSON format for log data retrieval
type logViewResponse struct {
	Data string `json:"data"`
}

// logSentResponse represents the response structure for log sending operations
// This includes size information and error details for debugging
type logSentResponse struct {
	Size  int64  `json:"size"`
	Error string `json:"error"`
}

// logReader provides read access to log data with size information
// This encapsulates the log reading functionality for external consumers
type logReader struct {
	r    io.ReadCloser
	size int64
}

// logWriter is an internal buffer to keep track of runtime log when no logging is enabled.
// This provides in-memory log storage for debugging and monitoring purposes
type logWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	size int
}

// newLogWriter creates an internal log writer.
// This provides the default log writer with standard buffer size
func newLogWriter() *logWriter {
	return newLogWriterWithSize(logWriterSize)
}

// newSmallLogWriter creates an internal log writer with small buffer size.
// This is used in memory-constrained environments or for temporary logging
func newSmallLogWriter() *logWriter {
	return newLogWriterWithSize(logWriterSmallSize)
}

// newLogWriterWithSize creates an internal log writer with a given buffer size.
// This allows customization of log buffer size based on specific requirements
func newLogWriterWithSize(size int) *logWriter {
	lw := &logWriter{size: size}
	return lw
}

// Write implements io.Writer interface for logWriter
// This manages buffer overflow by discarding old data while preserving important markers
func (lw *logWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	// If writing p causes overflows, discard old data.
	// This prevents unbounded memory growth while maintaining recent logs
	if lw.buf.Len()+len(p) > lw.size {
		buf := lw.buf.Bytes()
		haveEndMarker := false
		// If there's init end marker already, preserve the data til the marker.
		// This ensures initialization logs are always available for debugging
		if idx := bytes.LastIndex(buf, []byte(logWriterInitEndMarker)); idx >= 0 {
			buf = buf[:idx+len(logWriterInitEndMarker)]
			haveEndMarker = true
		} else {
			// Otherwise, preserve the initial size data.
			buf = buf[:logWriterInitialSize]
			if idx := bytes.LastIndex(buf, []byte("\n")); idx != -1 {
				buf = buf[:idx]
			}
		}
		lw.buf.Reset()
		lw.buf.Write(buf)
		if !haveEndMarker {
			lw.buf.WriteString(logWriterInitEndMarker) // indicate that the log was truncated.
		}
	}
	// If p is bigger than buffer size, truncate p by half until its size is smaller.
	for len(p)+lw.buf.Len() > lw.size {
		p = p[len(p)/2:]
	}
	return lw.buf.Write(p)
}

// initLogging initializes global logging setup.
func (p *prog) initLogging(backup bool) {
	logCores := initLoggingWithBackup(backup)

	// Initializing internal logging after global logging.
	p.initInternalLogging(logCores)
	p.logger.Store(mainLog.Load())
}

// initInternalLogging performs internal logging if there's no log enabled.
func (p *prog) initInternalLogging(externalCores []zapcore.Core) {
	if !p.needInternalLogging() {
		return
	}
	p.initInternalLogWriterOnce.Do(func() {
		p.Notice().Msg("internal logging enabled")
		p.internalLogWriter = newLogWriter()
		p.internalLogSent = time.Now().Add(-logWriterSentInterval)
		p.internalWarnLogWriter = newSmallLogWriter()
	})
	p.mu.Lock()
	lw := p.internalLogWriter
	wlw := p.internalWarnLogWriter
	p.mu.Unlock()

	// Create zap cores for different writers
	var cores []zapcore.Core
	cores = append(cores, externalCores...)

	// Add core for internal log writer.
	// Run the internal logging at debug level, so we could
	// have enough information for troubleshooting.
	internalCore := newHumanReadableZapCore(lw, zapcore.DebugLevel)
	cores = append(cores, internalCore)

	// Add core for internal warn log writer
	warnCore := newHumanReadableZapCore(wlw, zapcore.WarnLevel)
	cores = append(cores, warnCore)

	// Create a multi-core logger
	multiCore := zapcore.NewTee(cores...)
	logger := zap.New(multiCore)

	mainLog.Store(&ctrld.Logger{Logger: logger})
}

// needInternalLogging reports whether prog needs to run internal logging.
func (p *prog) needInternalLogging() bool {
	// Do not run in non-cd mode.
	if cdUID == "" {
		return false
	}
	// Do not run if there's already log file.
	if p.cfg.Service.LogPath != "" {
		return false
	}
	return true
}

func (p *prog) logReader() (*logReader, error) {
	if p.needInternalLogging() {
		p.mu.Lock()
		lw := p.internalLogWriter
		wlw := p.internalWarnLogWriter
		p.mu.Unlock()
		if lw == nil {
			return nil, errors.New("nil internal log writer")
		}
		if wlw == nil {
			return nil, errors.New("nil internal warn log writer")
		}
		// Normal log content.
		lw.mu.Lock()
		lwReader := bytes.NewReader(lw.buf.Bytes())
		lwSize := lw.buf.Len()
		lw.mu.Unlock()
		// Warn log content.
		wlw.mu.Lock()
		wlwReader := bytes.NewReader(wlw.buf.Bytes())
		wlwSize := wlw.buf.Len()
		wlw.mu.Unlock()
		reader := io.MultiReader(lwReader, bytes.NewReader([]byte(logWriterLogEndMarker)), wlwReader)
		lr := &logReader{r: io.NopCloser(reader)}
		lr.size = int64(lwSize + wlwSize)
		if lr.size == 0 {
			return nil, errors.New("internal log is empty")
		}
		return lr, nil
	}
	if p.cfg.Service.LogPath == "" {
		return &logReader{r: io.NopCloser(strings.NewReader(""))}, nil
	}
	f, err := os.Open(normalizeLogFilePath(p.cfg.Service.LogPath))
	if err != nil {
		return nil, err
	}
	lr := &logReader{r: f}
	if st, err := f.Stat(); err == nil {
		lr.size = st.Size()
	} else {
		return nil, fmt.Errorf("f.Stat: %w", err)
	}
	if lr.size == 0 {
		return nil, errors.New("log file is empty")
	}
	return lr, nil
}

// newHumanReadableZapCore creates a zap core optimized for human-readable log output.
//
// Features:
// - Uses development encoder configuration for enhanced readability
// - Console encoding with colored log levels for easy visual scanning
// - Millisecond precision timestamps in human-friendly format
// - Structured field output with clear key-value pairs
// - Ideal for development, debugging, and interactive terminal sessions
//
// Parameters:
//   - w: The output writer (e.g., os.Stdout, file, buffer)
//   - level: Minimum log level to capture (e.g., Debug, Info, Warn, Error)
//
// Returns a zapcore.Core configured for human consumption.
func newHumanReadableZapCore(w io.Writer, level zapcore.Level) zapcore.Core {
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.StampMilli)
	encoderConfig.EncodeLevel = noticeColorLevelEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	return zapcore.NewCore(encoder, zapcore.AddSync(w), level)
}

// newMachineFriendlyZapCore creates a zap core optimized for machine processing and log aggregation.
//
// Features:
// - Uses production encoder configuration for consistent, parseable output
// - Console encoding with non-colored log levels for log parsing tools
// - Millisecond precision timestamps in ISO-like format
// - Structured field output optimized for log aggregation systems
// - Ideal for production environments, log shipping, and automated analysis
//
// Parameters:
//   - w: The output writer (e.g., os.Stdout, file, buffer)
//   - level: Minimum log level to capture (e.g., Debug, Info, Warn, Error)
//
// Returns a zapcore.Core configured for machine consumption and log aggregation.
func newMachineFriendlyZapCore(w io.Writer, level zapcore.Level) zapcore.Core {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.StampMilli)
	encoderConfig.EncodeLevel = noticeLevelEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	return zapcore.NewCore(encoder, zapcore.AddSync(w), level)
}

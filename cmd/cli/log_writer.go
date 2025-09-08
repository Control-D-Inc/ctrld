package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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
	logWriterSize = 1024 * 1024 * 5 // 5 MB

	// logWriterSmallSize is used for memory-constrained environments
	// This reduces memory footprint while still maintaining log functionality
	logWriterSmallSize = 1024 * 1024 * 1 // 1 MB

	// logWriterInitialSize is the initial buffer allocation
	// This provides immediate space for early log entries
	logWriterInitialSize = 32 * 1024 // 32 KB

	// logWriterSentInterval controls how often logs are sent to external systems
	// This balances real-time logging with system performance
	logWriterSentInterval = time.Minute

	// logWriterInitEndMarker marks the end of initialization logs
	// This helps separate startup logs from runtime logs
	logWriterInitEndMarker = "\n\n=== INIT_END ===\n\n"

	// logWriterLogEndMarker marks the end of log sections
	// This provides clear boundaries for log parsing and analysis
	logWriterLogEndMarker = "\n\n=== LOG_END ===\n\n"
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

// logReader provides read access to log data with size information.
//
// This struct encapsulates log reading functionality for external consumers,
// providing both the log content and metadata about the log size. It supports
// reading from both internal log buffers (when no external logging is configured)
// and external log files (when logging to file is enabled).
//
// Fields:
//   - r: An io.ReadCloser that provides access to the log content
//   - size: The total size of the log data in bytes
//
// The logReader is used by the control server to serve log content to clients
// and by various CLI commands that need to display or process log data.
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
		p.Notice().Msg("Internal logging enabled")
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

// logReaderNoColor returns a logReader with ANSI color codes stripped from the log content.
//
// This method is useful when log content needs to be processed by tools that don't
// handle ANSI escape sequences properly, or when storing logs in plain text format.
// It internally calls logReader(true) to strip color codes.
//
// Returns:
//   - *logReader: A logReader instance with color codes removed, or nil if no logs available
//   - error: Any error encountered during log reading (e.g., empty logs, file access issues)
//
// Use cases:
//   - Log processing pipelines that require plain text
//   - Storing logs in databases or text files
//   - Displaying logs in environments that don't support color
func (p *prog) logReaderNoColor() (*logReader, error) {
	return p.logReader(true)
}

// logReaderRaw returns a logReader with ANSI color codes preserved in the log content.
//
// This method maintains the original formatting of log entries including color codes,
// which is useful for displaying logs in terminals that support ANSI colors or when
// the original visual formatting needs to be preserved. It internally calls logReader(false).
//
// Returns:
//   - *logReader: A logReader instance with color codes preserved, or nil if no logs available
//   - error: Any error encountered during log reading (e.g., empty logs, file access issues)
//
// Use cases:
//   - Terminal-based log viewers that support color
//   - Interactive debugging sessions
//   - Preserving original log formatting for display
func (p *prog) logReaderRaw() (*logReader, error) {
	return p.logReader(false)
}

// logReader creates a logReader instance for accessing log content with optional color stripping.
//
// This is the core method that handles log reading from different sources based on the
// current logging configuration. It supports both internal logging (when no external
// logging is configured) and external file logging (when logging to file is enabled).
//
// Behavior:
//   - Internal logging: Reads from internal log buffers (normal logs + warning logs)
//     and combines them with appropriate markers for separation
//   - External logging: Reads directly from the configured log file
//   - Empty logs: Returns appropriate error messages when no log content is available
//
// Parameters:
//   - stripColor: If true, removes ANSI color codes from log content; if false, preserves them
//
// Returns:
//   - *logReader: A logReader instance providing access to log content and size metadata
//   - error: Any error encountered during log reading, including:
//   - "nil internal log writer" - Internal logging not properly initialized
//   - "nil internal warn log writer" - Warning log writer not properly initialized
//   - "internal log is empty" - No content in internal log buffers
//   - "log file is empty" - External log file exists but contains no data
//   - File system errors when accessing external log files
//
// The method handles thread-safe access to internal log buffers and provides
// comprehensive error handling for various edge cases.
func (p *prog) logReader(stripColor bool) (*logReader, error) {
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
		lwReader := newLogReader(&lw.buf, stripColor)
		lwSize := lw.buf.Len()
		lw.mu.Unlock()
		// Warn log content.
		wlw.mu.Lock()
		wlwReader := newLogReader(&wlw.buf, stripColor)
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

// ansiRegex is a regular expression to match ANSI color codes.
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// newLogReader creates a reader for log buffer content with optional ANSI color stripping.
//
// This function provides flexible log content access by allowing consumers to choose
// between raw log data (with ANSI color codes) or stripped content (without color codes).
// The color stripping is useful when logs need to be processed by tools that don't
// handle ANSI escape sequences properly, or when storing logs in plain text format.
//
// Parameters:
//   - buf: The log buffer containing the log data to read
//   - stripColor: If true, strips ANSI color codes from the log content;
//     if false, returns raw log content with color codes preserved
//
// Returns an io.Reader that provides access to the processed log content.
func newLogReader(buf *bytes.Buffer, stripColor bool) io.Reader {
	if stripColor {
		return strings.NewReader(ansiRegex.ReplaceAllString(buf.String(), ""))
	}
	return strings.NewReader(buf.String())
}

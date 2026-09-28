package cli

import (
	"bytes"
	"encoding/json"
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

	logFileName = "ctrld.log"
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

// logSubscriber represents a subscriber to live log output.
type logSubscriber struct {
	ch chan []byte
}

// logWriter is an internal buffer to keep track of runtime log when no logging is enabled.
// When a file is configured via setLogFile, writes also go to that file, which
// rotates within its budget, so logs survive restarts.
type logWriter struct {
	mu          sync.Mutex
	buf         bytes.Buffer
	size        int
	subscribers []*logSubscriber

	file *rotatingFile
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
	return &logWriter{size: size}
}

// setLogFile persists the stream to a file that rotates within the budget.
func (lw *logWriter) setLogFile(path string, budget logBudget) error {
	rf, err := newRotatingFile(path, budget, nil)
	if err != nil {
		return err
	}
	rf.onRotate = emitLogRotated
	lw.mu.Lock()
	defer lw.mu.Unlock()
	lw.file = rf
	return nil
}

// closeLogFile closes the backing file if open.
func (lw *logWriter) closeLogFile() {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.file == nil {
		return
	}
	lw.file.close()
	lw.file = nil
}

// rotating returns the backing file, so a caller works with the file itself
// instead of one pass-through method for each of its calls. A stream that
// keeps its lines in memory only has no file.
func (lw *logWriter) rotating() *rotatingFile {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.file
}

// bufferedBytes copies the memory buffer, so a reader of the copy holds no
// writer lock while it works.
func (lw *logWriter) bufferedBytes() []byte {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	buffered := make([]byte, lw.buf.Len())
	copy(buffered, lw.buf.Bytes())
	return buffered
}

// Subscribe returns a channel that receives new log data as it's written,
// and an unsubscribe function to clean up when done.
func (lw *logWriter) Subscribe() (<-chan []byte, func()) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	sub := &logSubscriber{ch: make(chan []byte, 256)}
	lw.subscribers = append(lw.subscribers, sub)
	unsub := func() {
		lw.mu.Lock()
		defer lw.mu.Unlock()
		for i, s := range lw.subscribers {
			if s == sub {
				lw.subscribers = append(lw.subscribers[:i], lw.subscribers[i+1:]...)
				close(sub.ch)
				break
			}
		}
	}
	return sub.ch, unsub
}

// tailLastLines returns the last n lines from the current buffer.
func (lw *logWriter) tailLastLines(n int) []byte {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	data := lw.buf.Bytes()
	if n <= 0 || len(data) == 0 {
		return nil
	}
	// Find the last n newlines from the end.
	count := 0
	pos := len(data)
	for pos > 0 {
		pos--
		if data[pos] == '\n' {
			count++
			if count == n+1 {
				pos++ // move past this newline
				break
			}
		}
	}
	result := make([]byte, len(data)-pos)
	copy(result, data[pos:])
	return result
}

// Write implements io.Writer interface for logWriter
func (lw *logWriter) Write(p []byte) (int, error) {
	// The file takes the line outside lw.mu: it holds its own lock, and it
	// reports its rotation with an event that comes back through this writer.
	// A file error must not stop the memory buffer, which is the fallback for
	// the log readers.
	if rf := lw.rotating(); rf != nil {
		_, _ = rf.Write(p)
	}
	return lw.writeStreams(p)
}

// writeStreams feeds the subscribers and the memory buffer.
// This manages buffer overflow by discarding old data while preserving important markers
func (lw *logWriter) writeStreams(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	// Fan-out to subscribers (non-blocking).
	if len(lw.subscribers) > 0 {
		cp := make([]byte, len(p))
		copy(cp, p)
		for _, sub := range lw.subscribers {
			select {
			case sub.ch <- cp:
			default:
				// Drop if subscriber is slow to avoid blocking the logger.
			}
		}
	}

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

// emitLogRotated logs a rotation. The file that rotated guards this call,
// because the event is a line that can rotate that file again. A rotation
// that could not move the file keeps the lines it holds, so it earns a
// warning instead of the normal report.
func emitLogRotated(r logRotation) {
	event := journal(mainLog.Load().Info())
	message := "Log rotated"
	if r.err != nil {
		event = journal(mainLog.Load().Warn()).Err(r.err)
		message = "Log rotation failed"
	}
	event = event.Str("file", r.file).Int64("bytes_written", r.bytesWritten)
	// A file that holds a header only carries no event, and the year 1 of the
	// zero time reads as a wrong date.
	if !r.firstWrite.IsZero() {
		event = event.Time("first_event_at", r.firstWrite)
	}
	if !r.lastWrite.IsZero() {
		event = event.Time("last_event_at", r.lastWrite)
	}
	event.Int("backups", r.backups).Msg(message)
}

// initLogging initializes global logging setup.
func (p *prog) initLogging(backup bool) {
	logCores := initLoggingWithBackup(backup)

	// Initializing internal logging after global logging.
	p.initInternalLogging(logCores)
	p.logger.Store(mainLog.Load())

	if rf := logPathFile.Load(); rf != nil {
		p.refreshLogHeader()
		if err := rf.writeHeader(); err != nil {
			p.Warn().Err(err).Msg("Could not write log header")
		}
	}
	// A start-time backup happens before the logger reaches the new file, so
	// its event waits here for a logger that can report it.
	if record := pendingLogPathRotation.Swap(nil); record != nil {
		emitLogRotated(*record)
	}
}

// initLoggingAfterProvisioning opens the internal streams of a run whose
// resolver UID came from the provisioning token. The first logging setup ran
// before that UID was known, so it opened no debug file and no journal.
func (p *prog) initLoggingAfterProvisioning() {
	if !p.needInternalLogging() {
		return
	}
	if lw, _ := p.internalWriters(); lw != nil {
		return
	}
	p.initLogging(false)
}

// switchLogPath moves the logging of this run to the log_path that the API
// config set. The header of the new file leads it, the lines of an earlier
// local log_path file follow that header, and the internal streams close,
// because a run with a log_path keeps no internal files. A run without a local
// log_path carries no lines: its history stays in the internal debug stream,
// which this call closes.
func (p *prog) switchLogPath(oldLogPath, newLogPath string) {
	// After processCDFlags, log config may change, so reset mainLog and re-init logging.
	mainLog.Store(&ctrld.Logger{Logger: zap.NewNop()})

	carried := carriedLogLines(oldLogPath, newLogPath)
	p.initLogging(false)
	p.carryLogLines(carried)
}

// carriedLogLines reads the lines of the old log_path file and empties the new
// file, so the header of the new file leads it. It drops the header lines of
// the old file, because each of them names the old file.
func carriedLogLines(oldLogPath, newLogPath string) []byte {
	buf, err := os.ReadFile(oldLogPath)
	if err != nil {
		return nil
	}
	if err := os.Remove(newLogPath); err != nil && !os.IsNotExist(err) {
		mainLog.Load().Warn().Err(err).Msg("could not clear the new log file")
		return nil
	}
	return withoutLogHeaderLines(buf)
}

// carryLogLines appends the lines of the old log_path file below the header of
// the new one.
func (p *prog) carryLogLines(lines []byte) {
	if len(lines) == 0 {
		return
	}
	rf := logPathFile.Load()
	if rf == nil {
		return
	}
	if _, err := rf.Write(lines); err != nil {
		p.Warn().Err(err).Msg("Could not copy old log file")
	}
}

// withoutLogHeaderLines removes every header line of a log file.
func withoutLogHeaderLines(buf []byte) []byte {
	var kept bytes.Buffer
	for _, line := range bytes.SplitAfter(buf, []byte("\n")) {
		if isLogHeaderLine(line) {
			continue
		}
		kept.Write(line)
	}
	return kept.Bytes()
}

// isLogHeaderLine reports whether one line of a log file is a header line.
func isLogHeaderLine(line []byte) bool {
	var parsed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &parsed); err != nil {
		return false
	}
	return parsed.Message == logHeaderMessage
}

// initInternalLogging performs internal logging if there's no log enabled.
func (p *prog) initInternalLogging(externalCores []zapcore.Core) {
	if !p.needInternalLogging() {
		// A log_path that the API set takes over from the internal files.
		p.closeInternalLogs()
		return
	}
	headersWritten := false
	p.initInternalLogWriterOnce.Do(func() {
		// mainLog, not p.logger: a test drives this setup on a bare prog.
		mainLog.Load().Notice().Msg("Internal logging enabled")
		p.internalLogWriter = newLogWriter()
		p.internalLogSent = time.Now().Add(-logWriterSentInterval)
		p.internalJournalWriter = newSmallLogWriter()
		p.openInternalLogFiles()
		// A restart appends to the file it finds, so the header marks the
		// point where this run starts.
		p.refreshLogHeader()
		p.writeLogHeaders()
		headersWritten = true
	})
	lw, jlw := p.internalWriters()

	// Create zap cores for different writers
	cores := make([]zapcore.Core, 0, len(externalCores)+2)
	cores = append(cores, externalCores...)

	// Run the internal logging at debug level, so we could
	// have enough information for troubleshooting. The journal core keeps
	// the lines that survive a restart.
	cores = append(cores, newHumanReadableZapCore(lw, zapcore.DebugLevel), newJournalCore(jlw))

	// Create a multi-core logger
	mainLog.Store(&ctrld.Logger{Logger: zap.New(zapcore.NewTee(cores...))})
	if headersWritten {
		return
	}
	// A later call reaches a changed config, so the stored bytes need the new
	// values. The files keep the header they already hold.
	p.refreshLogHeader()
}

// openInternalLogFiles persists both internal streams, so they survive a
// restart.
func (p *prog) openInternalLogFiles() {
	_, journalBudget := logBudgets()
	openInternalLogFile(p.internalLogWriter, absHomeDir(logFileName), debugLogBudget(&p.cfg.Service), "internal")
	openInternalLogFile(p.internalJournalWriter, absHomeDir(journalLogFileName), journalBudget, "journal")
}

// openInternalLogFile persists one internal stream. A stream whose file cannot
// open keeps its lines in memory. Only these files get a prune: ctrld owns
// their names, while log_path can name a file in a directory that holds the
// files of other programs.
func openInternalLogFile(lw *logWriter, path string, budget logBudget, name string) {
	pruneNumberedBackups(path, budget.backups)
	if err := lw.setLogFile(path, budget); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("Could not enable persistent %s logging", name)
		return
	}
	mainLog.Load().Notice().Msgf("%s log file: %s", name, path)
}

// internalWriters returns the debug stream and the journal stream. Both stay
// nil until initInternalLogging opens them, and outside cd mode.
func (p *prog) internalWriters() (debugWriter, journalWriter *logWriter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.internalLogWriter, p.internalJournalWriter
}

// openLogFiles returns the files that this run writes, debug first. A stream
// that keeps its lines in memory only has no file, and log_path belongs to
// this list although no internal writer owns it.
func (p *prog) openLogFiles() []*rotatingFile {
	debugWriter, journalWriter := p.internalWriters()
	files := make([]*rotatingFile, 0, 3)
	for _, writer := range []*logWriter{debugWriter, journalWriter} {
		if writer == nil {
			continue
		}
		if rf := writer.rotating(); rf != nil {
			files = append(files, rf)
		}
	}
	if rf := logPathFile.Load(); rf != nil {
		files = append(files, rf)
	}
	return files
}

// closeInternalLogs closes both internal files, so a stop leaves no open
// handle behind.
func (p *prog) closeInternalLogs() {
	debugWriter, journalWriter := p.internalWriters()
	for _, writer := range []*logWriter{debugWriter, journalWriter} {
		if writer == nil {
			continue
		}
		writer.closeLogFile()
	}
}

// needInternalLogging reports whether prog needs to run internal logging.
func (p *prog) needInternalLogging() bool {
	// Do not run in silent mode: the user explicitly asked for no logging, so
	// ctrld must not create or write the persisted internal log file (nor reset
	// the global level back to debug). See https://github.com/Control-D-Inc/ctrld/issues/320.
	if silent {
		return false
	}
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
		return newANSIStripReader(strings.NewReader(buf.String()))
	}
	return strings.NewReader(buf.String())
}

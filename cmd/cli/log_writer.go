package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router"
)

const (
	logWriterSize          = 1024 * 1024 * 5 // 5 MB
	logWriterSmallSize     = 1024 * 1024 * 1 // 1 MB
	logWriterInitialSize   = 32 * 1024       // 32 KB
	logWriterSentInterval  = time.Minute
	logWriterInitEndMarker = "\n\n=== INIT_END ===\n\n"
	logWriterLogEndMarker  = "\n\n=== LOG_END ===\n\n"

	logFileName = "ctrld.log"
)

type logViewResponse struct {
	Data string `json:"data"`
}

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
func newLogWriter() *logWriter {
	return newLogWriterWithSize(logWriterSize)
}

// newSmallLogWriter creates an internal log writer with small buffer size.
func newSmallLogWriter() *logWriter {
	return newLogWriterWithSize(logWriterSmallSize)
}

// newLogWriterWithSize creates an internal log writer with a given buffer size.
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
	if lw.buf.Len()+len(p) > lw.size {
		buf := lw.buf.Bytes()
		haveEndMarker := false
		// If there's init end marker already, preserve the data til the marker.
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
	zerolog.TimeFieldFormat = time.RFC3339 + ".000"
	logWriters := initLoggingWithBackup(backup)

	// Initializing internal logging after global logging.
	p.initInternalLogging(logWriters)

	if rf := logPathFile.Load(); rf != nil {
		p.refreshLogHeader()
		if err := rf.writeHeader(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("could not write log header")
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
	discard := zerolog.New(io.Discard)
	mainLog.Store(&discard)

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
		mainLog.Load().Warn().Err(err).Msg("could not copy old log file")
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
func (p *prog) initInternalLogging(writers []io.Writer) {
	if !p.needInternalLogging() {
		// A log_path that the API set takes over from the internal files.
		p.closeInternalLogs()
		return
	}
	headersWritten := false
	var headerRotations []logRotation
	p.initInternalLogWriterOnce.Do(func() {
		mainLog.Load().Notice().Msg("internal logging enabled")
		p.internalLogWriter = newLogWriter()
		p.internalLogSent = time.Now().Add(-logWriterSentInterval)
		p.internalJournalWriter = newSmallLogWriter()
		p.openInternalLogFiles()
		// A restart appends to the file it finds, so the header marks the
		// point where this run starts.
		p.refreshLogHeader()
		headerRotations = p.writeLogHeaders()
		headersWritten = true
	})
	lw, jlw := p.internalWriters()
	// If ctrld was run without explicit verbose level,
	// run the internal logging at debug level, so we could
	// have enough information for troubleshooting.
	if verbose == 0 {
		wrapConsoleWritersAtNotice(writers)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	writers = append(writers, lw, newJournalLevelWriter(jlw))
	multi := zerolog.MultiLevelWriter(writers...)
	l := mainLog.Load().Output(multi).With().Logger()
	mainLog.Store(&l)
	ctrld.ProxyLogger.Store(&l)
	// A header that crossed the budget rotated its file before the logger
	// reached the files, so its event waits for this logger.
	for _, rotated := range headerRotations {
		emitLogRotated(rotated)
	}
	if headersWritten {
		return
	}
	// A later call reaches a changed config, so the stored bytes need the new
	// values. The files keep the header they already hold.
	p.applyDebugLogBudget(debugLogBudget(&p.cfg.Service, router.Name() != ""))
	p.refreshLogHeader()
}

// applyDebugLogBudget gives the open debug files the limits of the config that
// runs now. The files open before the API config arrives, and a managed config
// refresh can change the limits with no restart. Only the internal file gets a
// prune: ctrld owns its name, while log_path can name a file in a directory
// that holds the files of other programs.
func (p *prog) applyDebugLogBudget(budget logBudget) {
	if debugWriter, _ := p.internalWriters(); debugWriter != nil {
		if rf := debugWriter.rotating(); rf != nil {
			rf.setBudget(budget)
			pruneNumberedBackups(rf.currentPath(), budget.backups)
		}
	}
	if rf := logPathFile.Load(); rf != nil {
		rf.setBudget(budget)
	}
}

// wrapConsoleWritersAtNotice holds the console at notice level while the files
// take every level. A run without -v needs the detail for troubleshooting, and
// the same detail on the console is noise.
func wrapConsoleWritersAtNotice(writers []io.Writer) {
	for i := range writers {
		writers[i] = &zerolog.FilteredLevelWriter{
			Writer: zerolog.LevelWriterAdapter{Writer: writers[i]},
			Level:  zerolog.NoticeLevel,
		}
	}
}

// openInternalLogFiles persists both internal streams, so they survive a
// restart.
func (p *prog) openInternalLogFiles() {
	isRouter := router.Name() != ""
	_, journalBudget := logBudgets(isRouter)
	openInternalLogFile(p.internalLogWriter, absHomeDir(logFileName), debugLogBudget(&p.cfg.Service, isRouter), "internal")
	openInternalLogFile(p.internalJournalWriter, absHomeDir(journalLogFileName), journalBudget, "journal")
}

// openInternalLogFile persists one internal stream. A stream whose file cannot
// open keeps its lines in memory. Only these files get a prune: ctrld owns
// their names, while log_path can name a file in a directory that holds the
// files of other programs.
func openInternalLogFile(lw *logWriter, path string, budget logBudget, name string) {
	pruneNumberedBackups(path, budget.backups)
	if err := lw.setLogFile(path, budget); err != nil {
		mainLog.Load().Warn().Err(err).Msgf("could not enable persistent %s logging", name)
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

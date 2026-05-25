package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

const (
	logWriterSize          = 1024 * 1024 * 5 // 5 MB
	logWriterSmallSize     = 1024 * 1024 * 1 // 1 MB
	logWriterInitialSize   = 32 * 1024       // 32 KB
	logWriterSentInterval  = time.Minute
	logWriterInitEndMarker = "\n\n=== INIT_END ===\n\n"
	logWriterLogEndMarker  = "\n\n=== LOG_END ===\n\n"

	logFileName    = "ctrld.log"
	logFileMaxSize = 1024 * 1024 * 5 // 5 MB
)

type logViewResponse struct {
	Data string `json:"data"`
}

type logSentResponse struct {
	Size  int64  `json:"size"`
	Error string `json:"error"`
}

type logReader struct {
	r    io.ReadCloser
	size int64
}

// logSubscriber represents a subscriber to live log output.
type logSubscriber struct {
	ch chan []byte
}

// logWriter is an internal buffer to keep track of runtime log when no logging is enabled.
// When a file path is configured via setLogFile, writes are also persisted to
// a rotated file on disk (max logFileMaxSize, 1 backup) so logs survive restarts.
type logWriter struct {
	mu          sync.Mutex
	buf         bytes.Buffer
	size        int
	subscribers []*logSubscriber

	// File persistence fields.
	logFile     *os.File
	logFilePath string
	logFileSize int64
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
	lw := &logWriter{size: size}
	return lw
}

// setLogFile configures file-backed persistence for the log writer.
// The directory is created if it does not exist. An existing file is
// opened in append mode and its current size is tracked for rotation.
func (lw *logWriter) setLogFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	lw.mu.Lock()
	defer lw.mu.Unlock()
	lw.logFile = f
	lw.logFilePath = path
	lw.logFileSize = st.Size()
	return nil
}

// rotateLogFile rotates the current log file to a .1 backup.
// It returns true if lw.logFile is usable after the call, false otherwise.
// Must be called with lw.mu held.
func (lw *logWriter) rotateLogFile() bool {
	if lw.logFile == nil {
		return false
	}
	lw.logFile.Close()
	backupPath := lw.logFilePath + ".1"
	// Best effort: rename current to backup (overwrites old backup).
	os.Rename(lw.logFilePath, backupPath)
	f, err := os.OpenFile(lw.logFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		// If we can't reopen, disable file logging.
		lw.logFile = nil
		lw.logFileSize = 0
		return false
	}
	lw.logFile = f
	lw.logFileSize = 0
	return true
}

// closeLogFile closes the backing file if open.
func (lw *logWriter) closeLogFile() {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.logFile != nil {
		lw.logFile.Close()
		lw.logFile = nil
	}
}

// logFilePaths returns the paths to the current log file and its backup
// (if they exist) for inclusion in log send payloads.
func (lw *logWriter) logFilePaths() (current, backup string) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.logFilePath == "" {
		return "", ""
	}
	current = lw.logFilePath
	bp := lw.logFilePath + ".1"
	if _, err := os.Stat(bp); err == nil {
		backup = bp
	}
	return current, backup
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

	// Write to backing file if configured.
	if lw.logFile != nil {
		needsRotation := lw.logFileSize+int64(len(p)) > logFileMaxSize
		if !needsRotation || lw.rotateLogFile() {
			if n, err := lw.logFile.Write(p); err == nil {
				lw.logFileSize += int64(n)
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

// initLogging initializes global logging setup.
func (p *prog) initLogging(backup bool) {
	zerolog.TimeFieldFormat = time.RFC3339 + ".000"
	logWriters := initLoggingWithBackup(backup)

	// Initializing internal logging after global logging.
	p.initInternalLogging(logWriters)
}

// internalLogFilePath returns the path for persisted internal logs.
// The file lives in the ctrld home directory alongside other runtime state.
func internalLogFilePath() string {
	return absHomeDir(logFileName)
}

// initInternalLogging performs internal logging if there's no log enabled.
func (p *prog) initInternalLogging(writers []io.Writer) {
	if !p.needInternalLogging() {
		return
	}
	p.initInternalLogWriterOnce.Do(func() {
		mainLog.Load().Notice().Msg("internal logging enabled")
		p.internalLogWriter = newLogWriter()
		p.internalLogSent = time.Now().Add(-logWriterSentInterval)
		p.internalWarnLogWriter = newSmallLogWriter()
		// Persist internal logs to disk so they survive restarts.
		if path := internalLogFilePath(); path != "" {
			if err := p.internalLogWriter.setLogFile(path); err != nil {
				mainLog.Load().Warn().Err(err).Msg("could not enable persistent internal logging")
			} else {
				mainLog.Load().Notice().Msgf("internal log file: %s", path)
			}
		}
	})
	p.mu.Lock()
	lw := p.internalLogWriter
	wlw := p.internalWarnLogWriter
	p.mu.Unlock()
	// If ctrld was run without explicit verbose level,
	// run the internal logging at debug level, so we could
	// have enough information for troubleshooting.
	if verbose == 0 {
		for i := range writers {
			w := &zerolog.FilteredLevelWriter{
				Writer: zerolog.LevelWriterAdapter{Writer: writers[i]},
				Level:  zerolog.NoticeLevel,
			}
			writers[i] = w
		}
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	writers = append(writers, lw)
	writers = append(writers, &zerolog.FilteredLevelWriter{
		Writer: zerolog.LevelWriterAdapter{Writer: wlw},
		Level:  zerolog.WarnLevel,
	})
	multi := zerolog.MultiLevelWriter(writers...)
	l := mainLog.Load().Output(multi).With().Logger()
	mainLog.Store(&l)
	ctrld.ProxyLogger.Store(&l)
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

		// If we have a persisted log file, read from disk (includes data
		// from previous runs that the in-memory buffer wouldn't have).
		current, backup := lw.logFilePaths()
		if current != "" {
			return p.logReaderFromFiles(current, backup, wlw)
		}

		// Fall back to in-memory buffer.
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

// logReaderFromFiles builds a logReader that concatenates the backup file
// (if it exists), the current log file, and the in-memory warn log buffer.
func (p *prog) logReaderFromFiles(current, backup string, wlw *logWriter) (*logReader, error) {
	var rcs []io.ReadCloser
	var totalSize int64

	closeAll := func() {
		for _, rc := range rcs {
			rc.Close()
		}
	}

	// Read backup file first (older entries).
	if backup != "" {
		if bf, err := os.Open(backup); err == nil {
			if st, err := bf.Stat(); err == nil {
				totalSize += st.Size()
			}
			rcs = append(rcs, bf)
		}
	}

	// Read current file.
	cf, err := os.Open(current)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("opening current log file: %w", err)
	}
	if st, err := cf.Stat(); err == nil {
		totalSize += st.Size()
	}
	rcs = append(rcs, cf)

	// Append warn log content from memory.
	wlw.mu.Lock()
	warnData := make([]byte, wlw.buf.Len())
	copy(warnData, wlw.buf.Bytes())
	wlw.mu.Unlock()

	if len(warnData) > 0 {
		rcs = append(rcs, io.NopCloser(bytes.NewReader([]byte(logWriterLogEndMarker))))
		rcs = append(rcs, io.NopCloser(bytes.NewReader(warnData)))
		totalSize += int64(len(logWriterLogEndMarker) + len(warnData))
	}

	if totalSize == 0 {
		closeAll()
		return nil, errors.New("internal log is empty")
	}

	readers := make([]io.Reader, len(rcs))
	closers := make([]io.Closer, len(rcs))
	for i, rc := range rcs {
		readers[i] = rc
		closers[i] = rc
	}
	combined := io.MultiReader(readers...)
	lr := &logReader{
		r:    &multiCloser{Reader: combined, closers: closers},
		size: totalSize,
	}
	return lr, nil
}

// multiCloser wraps an io.Reader and closes multiple underlying closers.
type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (mc *multiCloser) Close() error {
	var firstErr error
	for _, c := range mc.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

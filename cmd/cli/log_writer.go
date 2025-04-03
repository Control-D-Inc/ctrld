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

// logWriter is an internal buffer to keep track of runtime log when no logging is enabled.
type logWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	size int
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

func (lw *logWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

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
	mainLog.Store(&ctrld.Logger{Logger: &l})
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

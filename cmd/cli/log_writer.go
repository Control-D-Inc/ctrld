package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

const (
	logWriterSize        = 1024 * 1024 * 5 // 5 MB
	logWriterInitialSize = 32              // 32 B
	logSentInterval      = time.Minute
	logTruncatedMarker   = "...\n"
)

type logViewResponse struct {
	Data string `json:"data"`
}

// logWriter is an internal buffer to keep track of runtime log when no logging is enabled.
type logWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	size int
}

// newLogWriter creates an internal log writer with a fixed buffer size.
func newLogWriter() *logWriter {
	lw := &logWriter{size: logWriterSize}
	return lw
}

func (lw *logWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	// If writing p causes overflows, discard old data.
	if lw.buf.Len()+len(p) > lw.size {
		buf := lw.buf.Bytes()
		buf = buf[:logWriterInitialSize]
		if idx := bytes.LastIndex(buf, []byte("\n")); idx != -1 {
			buf = buf[:idx]
		}
		lw.buf.Reset()
		lw.buf.Write(buf)
		lw.buf.WriteString(logTruncatedMarker) // indicate that the log was truncated.
	}
	// If p is bigger than buffer size, truncate p by half until its size is smaller.
	for len(p)+lw.buf.Len() > lw.size {
		p = p[len(p)/2:]
	}
	return lw.buf.Write(p)
}

// initInternalLogging performs internal logging if there's no log enabled.
func (p *prog) initInternalLogging(writers []io.Writer) {
	if !p.needInternalLogging() {
		return
	}
	p.initInternalLogWriterOnce.Do(func() {
		mainLog.Load().Notice().Msg("internal logging enabled")
		lw := newLogWriter()
		p.internalLogWriter = lw
		p.internalLogSent = time.Now().Add(-logSentInterval)
	})
	p.mu.Lock()
	lw := p.internalLogWriter
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

func (p *prog) logContent() ([]byte, error) {
	var data []byte
	if p.needInternalLogging() {
		p.mu.Lock()
		lw := p.internalLogWriter
		p.mu.Unlock()
		if lw == nil {
			return nil, errors.New("nil internal log writer")
		}
		lw.mu.Lock()
		data = lw.buf.Bytes()
		lw.mu.Unlock()
	} else {
		if p.cfg.Service.LogPath == "" {
			return nil, nil
		}
		buf, err := os.ReadFile(normalizeLogFilePath(p.cfg.Service.LogPath))
		if err != nil {
			return nil, err
		}
		data = buf
	}
	return data, nil
}

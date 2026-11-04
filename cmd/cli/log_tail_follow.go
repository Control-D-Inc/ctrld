package cli

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"
)

// logTailPollInterval is the time between two reads of a tailed log file.
const logTailPollInterval = 200 * time.Millisecond

// followLogFile streams the lines of path until ctx ends. It first sends the
// last numLines lines, or starts at the end when numLines is 0. A rotation
// moves the file away or truncates it, so the poll reopens the path when the
// file behind it changes or shrinks.
func followLogFile(ctx context.Context, w io.Writer, flusher http.Flusher, path string, numLines int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { f.Close() }()

	if numLines > 0 {
		if tail := tailFileLastLines(f, numLines); len(tail) > 0 {
			w.Write(tail)
			flusher.Flush()
		}
	} else {
		f.Seek(0, io.SeekEnd)
	}

	buf := make([]byte, 4096)
	ticker := time.NewTicker(logTailPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n, err := f.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil && err != io.EOF {
				return
			}
			if n == 0 && logFileReplaced(f, path) {
				reopened, err := os.Open(path)
				if err != nil {
					continue
				}
				f.Close()
				f = reopened
			}
		case <-ctx.Done():
			return
		}
	}
}

// logFileReplaced reports whether path names another file than f, or a file
// shorter than the read position. Both mean that a rotation happened.
func logFileReplaced(f *os.File, path string) bool {
	current, err := os.Stat(path)
	if err != nil {
		return false
	}
	open, err := f.Stat()
	if err != nil {
		return true
	}
	if !os.SameFile(current, open) {
		return true
	}
	position, err := f.Seek(0, io.SeekCurrent)
	return err == nil && current.Size() < position
}

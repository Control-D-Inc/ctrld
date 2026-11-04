package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
)

// logSendDebugBudget bounds the debug bytes of one upload. The journal is
// always whole, so an upload stays small and keeps the retained stream. A test
// lowers it, because a few small files must cross it.
var logSendDebugBudget int64 = 10 << 20

// lineScanBufferSize bounds the memory that the search for a line boundary
// needs, whatever the length of the line.
const lineScanBufferSize = 32 * 1024

var (
	errInternalLogEmpty = errors.New("internal log is empty")
	errLogFileEmpty     = errors.New("log file is empty")
)

type logReader struct {
	r    io.ReadCloser
	size int64
}

// logFilePart is the part of one open log file that an upload carries. An
// offset of 0 means the whole file. size is the size at the open, so a write
// after the selection stays out of the upload and the budget holds.
type logFilePart struct {
	path   string
	f      *os.File
	offset int64
	size   int64
}

// logReader composes the upload of the current logging mode and leads it with
// the header of this request. full lifts the bound on the debug bytes.
// stripColor removes the color codes of the internal debug stream, which an
// upload must not carry. The size counts the bytes before that removal.
func (p *prog) logReader(full, stripColor bool) (*logReader, error) {
	lr, err := p.modeLogReader(full)
	if err != nil {
		return nil, err
	}
	// An empty upload must stay empty, because the handlers answer 301 on a
	// size of 0.
	if lr.size == 0 {
		return lr, nil
	}
	header := p.sendLogHeader()
	var body io.Reader = io.MultiReader(bytes.NewReader(header), lr.r)
	if stripColor {
		body = newANSIStripReader(body)
	}
	return &logReader{
		r:    &multiCloser{Reader: body, closers: []io.Closer{lr.r}},
		size: lr.size + int64(len(header)),
	}, nil
}

// ansiStripChunkSize is the size of one read from the source of an
// ansiStripReader.
const ansiStripChunkSize = 32 * 1024

// ansiStripReader removes the ANSI color codes from what r yields. The level
// encoder of the internal debug stream colors each level, and an upload must
// hold plain text.
type ansiStripReader struct {
	r io.Reader
	// pending holds the bytes that are read and not yet stripped. It ends in
	// an escape sequence that the next chunk completes, or it is empty.
	pending []byte
	// out holds the stripped bytes that no Read took yet.
	out []byte
	err error
}

func newANSIStripReader(r io.Reader) io.Reader {
	return &ansiStripReader{r: r}
}

func (s *ansiStripReader) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		s.fill()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// fill reads one chunk and strips the bytes that hold no unfinished escape
// sequence. An unfinished sequence waits for the next chunk. The end of the
// source flushes everything, because nothing can complete the sequence.
func (s *ansiStripReader) fill() {
	chunk := make([]byte, ansiStripChunkSize)
	n, err := s.r.Read(chunk)
	s.pending = append(s.pending, chunk[:n]...)
	keep := 0
	if err == nil {
		keep = partialEscapeLen(s.pending)
	}
	ready := len(s.pending) - keep
	s.out = ansiRegex.ReplaceAll(s.pending[:ready], nil)
	s.pending = append([]byte(nil), s.pending[ready:]...)
	s.err = err
}

// partialEscapeLen returns the length of the escape sequence that starts in b
// and does not end in it, or 0 when b ends outside a sequence.
func partialEscapeLen(b []byte) int {
	start := bytes.LastIndexByte(b, 0x1b)
	if start < 0 {
		return 0
	}
	tail := b[start:]
	if len(tail) == 1 {
		return 1
	}
	if tail[1] != '[' {
		return 0
	}
	for _, c := range tail[2:] {
		if (c < '0' || c > '9') && c != ';' {
			return 0
		}
	}
	return len(tail)
}

// modeLogReader composes the body of the current logging mode.
func (p *prog) modeLogReader(full bool) (*logReader, error) {
	if p.needInternalLogging() {
		return p.internalLogReader(full)
	}
	return p.logPathReader(full)
}

// internalLogReader puts the newest debug bytes first, then the marker, then
// the journal, so a support reader finds the retained stream after the marker.
func (p *prog) internalLogReader(full bool) (*logReader, error) {
	lw, jlw := p.internalWriters()
	if lw == nil {
		return nil, errors.New("nil internal log writer")
	}
	if jlw == nil {
		return nil, errors.New("nil internal journal writer")
	}

	var upload logParts
	debugBytes := upload.addStream(lw, logSendBudget(full))
	upload.addBytes([]byte(logWriterLogEndMarker))
	journalBytes := upload.addStream(jlw, 0)
	// The marker alone is not a log, and the handlers answer 301 on an empty
	// upload.
	if debugBytes+journalBytes == 0 {
		upload.close()
		return nil, errInternalLogEmpty
	}
	return upload.reader(errInternalLogEmpty)
}

// logPathReader composes the upload of the log_path stream. The journal needs
// internal logging, so this upload holds the debug files alone. A run that
// opened no log_path file has nothing to send.
func (p *prog) logPathReader(full bool) (*logReader, error) {
	rf := logPathFile.Load()
	if p.cfg.Service.LogPath == "" || rf == nil {
		return emptyLogReader(), nil
	}
	var upload logParts
	upload.addBoundedFiles(rf.paths(), logSendBudget(full))
	return upload.reader(errLogFileEmpty)
}

// emptyLogReader yields no bytes, so the handlers answer 301 instead of
// sending an upload without a line.
func emptyLogReader() *logReader {
	return &logReader{r: io.NopCloser(strings.NewReader(""))}
}

// logSendBudget reports the debug bytes that one upload may carry. Zero means
// every file.
func logSendBudget(full bool) int64 {
	if full {
		return 0
	}
	return logSendDebugBudget
}

// boundedLogFiles opens the files, reads each size once, and picks the newest
// bytes that fit in budget. files come oldest first, and so do the parts. The
// oldest part starts at a line boundary, so the upload holds whole lines only.
// A budget of 0 or less takes every file. The files that fall out of the
// budget close here; the parts own the files they hold.
func boundedLogFiles(files []string, budget int64) []logFilePart {
	parts := openLogParts(files)
	remaining := budget
	first := len(parts)
	for first > 0 {
		part := &parts[first-1]
		if budget <= 0 || part.size <= remaining {
			remaining -= part.size
			first--
			continue
		}
		if offset, ok := lineStartAt(part.f, part.size-remaining); ok {
			part.offset = offset
			first--
		}
		// Without a line boundary in the tail, the upload would start inside a
		// line, so the file stays out.
		break
	}
	for _, part := range parts[:first] {
		part.f.Close()
	}
	return parts[first:]
}

// openLogParts opens each file through the platform opener, whose share flags
// let a rotation move the file away while Windows reads it. A rotation can
// also move a file away between the listing and the open, so a file that does
// not open must not stop the rest.
func openLogParts(files []string) []logFilePart {
	parts := make([]logFilePart, 0, len(files))
	for _, path := range files {
		f, err := openLogFile(path, os.O_RDONLY)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}
		parts = append(parts, logFilePart{path: path, f: f, size: st.Size()})
	}
	return parts
}

// lineStartAt returns the offset where a whole line starts at or after from.
// A cut that already lands on a line start keeps the line that follows it. It
// reports false when no newline follows.
func lineStartAt(f *os.File, from int64) (int64, bool) {
	if startsLine(f, from) {
		return from, true
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return 0, false
	}
	buf := make([]byte, lineScanBufferSize)
	offset := from
	for {
		n, readErr := f.Read(buf)
		if index := bytes.IndexByte(buf[:n], '\n'); index >= 0 {
			return offset + int64(index) + 1, true
		}
		offset += int64(n)
		if readErr != nil {
			return 0, false
		}
	}
}

// startsLine reports whether from is the first byte of a line.
func startsLine(f *os.File, from int64) bool {
	if from == 0 {
		return true
	}
	var previous [1]byte
	if _, err := f.ReadAt(previous[:], from-1); err != nil {
		return false
	}
	return previous[0] == '\n'
}

// logParts collects the readers of one upload and the files it must close.
type logParts struct {
	readers []io.Reader
	closers []io.Closer
	size    int64
}

func (lp *logParts) addBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	lp.readers = append(lp.readers, bytes.NewReader(b))
	lp.size += int64(len(b))
}

// addFiles takes the open parts. Each reader ends at the size of the open, so
// the bytes that a writer adds later stay out of this upload.
func (lp *logParts) addFiles(parts []logFilePart) {
	for _, part := range parts {
		length := part.size - part.offset
		if length <= 0 {
			part.f.Close()
			continue
		}
		lp.readers = append(lp.readers, io.NewSectionReader(part.f, part.offset, length))
		lp.closers = append(lp.closers, part.f)
		lp.size += length
	}
}

// addBoundedFiles adds the newest bytes of files that fit in budget. A budget
// of 0 or less takes every file.
func (lp *logParts) addBoundedFiles(files []string, budget int64) {
	lp.addFiles(boundedLogFiles(files, budget))
}

// addStream adds the bytes of one stream and reports how many it added. A
// stream that has a file takes its files, and a stream that keeps its lines in
// memory takes its buffer, so one failed file never hides the other stream.
func (lp *logParts) addStream(lw *logWriter, budget int64) int64 {
	before := lp.size
	if rf := lw.rotating(); rf != nil {
		lp.addBoundedFiles(rf.paths(), budget)
		return lp.size - before
	}
	lp.addBytes(lw.bufferedBytes())
	return lp.size - before
}

// reader joins the parts. The size is the number of bytes that the reader
// yields, so the caller reports what it uploads.
func (lp *logParts) reader(empty error) (*logReader, error) {
	if lp.size == 0 {
		lp.close()
		return nil, empty
	}
	return &logReader{
		r:    &multiCloser{Reader: io.MultiReader(lp.readers...), closers: lp.closers},
		size: lp.size,
	}, nil
}

func (lp *logParts) close() {
	for _, c := range lp.closers {
		c.Close()
	}
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

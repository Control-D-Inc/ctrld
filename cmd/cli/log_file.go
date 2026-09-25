package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// errLogFileNotOpen tells a caller that the file is closed, so a write that
// returns no bytes never looks like a success.
var errLogFileNotOpen = errors.New("log file is not open")

// retryOpenInterval is the wait between two attempts to open a log file that
// could not open. A file error is often short-lived, and one attempt for each
// line would cost a system call for every line.
var retryOpenInterval = time.Minute

// logBudget is the disk space of one log stream: the size of the current
// file and the number of numbered backups that follow it.
type logBudget struct {
	maxSize int64
	backups int
}

// logRotation describes the file that a rotation moved away. A set err means
// that the file could not move, so the stream continues in the same file.
type logRotation struct {
	file         string
	bytesWritten int64
	firstWrite   time.Time
	lastWrite    time.Time
	backups      int
	err          error
}

// rotatingFile writes one log file and rotates it by size with numbered
// backups. It holds the header bytes, so every file it opens starts with
// the header, and it records the write times that the rotation event needs.
type rotatingFile struct {
	mu         sync.Mutex
	path       string
	budget     logBudget
	open       func(string, int) (*os.File, error)
	rename     func(oldpath, newpath string) error
	f          *os.File
	size       int64
	firstWrite time.Time
	lastWrite  time.Time
	header     []byte
	openErr    error
	onRotate   func(logRotation)
	// headerWritten tells whether the file that is open now already holds the
	// header. A start wires its logging more than once, and each file takes
	// one header.
	headerWritten bool
	// rotateFailedAt is the size at which a rotation could not move the file.
	// The next try waits for another budget of data, so a directory that
	// refuses the move does not cost one attempt per line.
	rotateFailedAt int64
	// retryOpenAt is the time from which a closed file may open again.
	retryOpenAt time.Time
	// rotatedInFlight keeps onRotate from reporting a rotation that the
	// rotation event itself caused.
	rotatedInFlight atomic.Bool
}

// newRotatingFile opens path in append mode and counts what it already holds,
// so a restart continues the current file instead of starting a new one.
func newRotatingFile(path string, budget logBudget, open func(string, int) (*os.File, error)) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}
	rf := &rotatingFile{path: path, budget: budget, open: open}
	f, err := rf.openFile(os.O_CREATE | os.O_RDWR | os.O_APPEND)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log file: %w", err)
	}
	rf.f = f
	rf.size = st.Size()
	return rf, nil
}

// openFile opens the file through the platform helper, which holds the flags
// that each platform needs: a share mode on Windows, and a refusal to follow
// a symlink elsewhere.
func (rf *rotatingFile) openFile(flags int) (*os.File, error) {
	if rf.open == nil {
		return openLogFile(rf.path, flags)
	}
	return rf.open(rf.path, flags)
}

func (rf *rotatingFile) renameFile(oldpath, newpath string) error {
	if rf.rename == nil {
		return os.Rename(oldpath, newpath)
	}
	return rf.rename(oldpath, newpath)
}

// writeReporting appends p and reports a rotation that happened first. It
// never calls onRotate, because the caller must log the rotation outside of
// the lock.
func (rf *rotatingFile) writeReporting(p []byte) (int, *logRotation, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	var rotated *logRotation
	if rf.needsRotation(len(p)) {
		var err error
		if rotated, err = rf.rotateLocked(); err != nil {
			return 0, rotated, err
		}
	}
	n, err := rf.writeLocked(p)
	if err != nil {
		return n, rotated, err
	}
	rf.noteEventWrite()
	return n, rotated, nil
}

// Write makes the file an io.Writer for the logger. It reports the rotation
// after the lock is free, so the rotation event can go back into this file.
func (rf *rotatingFile) Write(p []byte) (int, error) {
	n, rotated, err := rf.writeReporting(p)
	if rotated == nil || !rf.rotatedInFlight.CompareAndSwap(false, true) {
		return n, err
	}
	defer rf.rotatedInFlight.Store(false)
	rf.mu.Lock()
	onRotate := rf.onRotate
	rf.mu.Unlock()
	if onRotate != nil {
		onRotate(*rotated)
	}
	return n, err
}

// setHeader stores a copy of the header bytes for the next file.
func (rf *rotatingFile) setHeader(b []byte) {
	header := make([]byte, len(b))
	copy(header, b)
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.header = header
}

// writeHeader appends the stored header to the current file, once for each
// file that the writer opens. A restart uses it to mark the point where the
// new run continues an old file.
func (rf *rotatingFile) writeHeader() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.headerWritten {
		return nil
	}
	return rf.writeHeaderLocked()
}

// setBudget takes the disk space of a later config. The file stays open, so a
// changed key costs no second header.
func (rf *rotatingFile) setBudget(budget logBudget) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.budget = budget
}

// rotateNow rotates the file although the budget is not spent.
func (rf *rotatingFile) rotateNow() (*logRotation, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.rotateLocked()
}

// paths returns the files that exist, oldest first, for the log readers.
func (rf *rotatingFile) paths() []string {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	files := make([]string, 0, rf.budget.backups+1)
	for i := rf.budget.backups; i >= 1; i-- {
		backup := rf.backupPath(i)
		if _, err := os.Stat(backup); err == nil {
			files = append(files, backup)
		}
	}
	if _, err := os.Stat(rf.path); err == nil {
		files = append(files, rf.path)
	}
	return files
}

func (rf *rotatingFile) currentPath() string {
	return rf.path
}

func (rf *rotatingFile) close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.f == nil {
		return nil
	}
	err := rf.f.Close()
	rf.f = nil
	return err
}

func (rf *rotatingFile) backupPath(index int) string {
	return fmt.Sprintf("%s.%d", rf.path, index)
}

// rotatingSuffix marks the file that a rotation with no backup moves away
// before it opens the new file. The old bytes stay behind the readers that
// hold them open, and the file goes as soon as the new file is open.
const rotatingSuffix = ".rotating"

func (rf *rotatingFile) rotatingPath() string {
	return rf.path + rotatingSuffix
}

// rotatedPath names the file that the next rotation leaves behind.
func (rf *rotatingFile) rotatedPath() string {
	if rf.budget.backups == 0 {
		return rf.path
	}
	return rf.backupPath(1)
}

// needsRotation reports whether p makes the file cross its budget. A closed
// file never rotates, because a rotation would shift the backups away for a
// write that cannot land.
func (rf *rotatingFile) needsRotation(n int) bool {
	if rf.f == nil || rf.budget.maxSize <= 0 {
		return false
	}
	return rf.size+int64(n) > rf.rotateFailedAt+rf.budget.maxSize
}

// rotateLocked moves the current file away and opens an empty one in its
// place. It must run with rf.mu held.
func (rf *rotatingFile) rotateLocked() (*logRotation, error) {
	record := &logRotation{
		file:         rf.rotatedPath(),
		bytesWritten: rf.size,
		firstWrite:   rf.firstWrite,
		lastWrite:    rf.lastWrite,
		backups:      rf.budget.backups,
	}
	if rf.f != nil {
		rf.f.Close()
		rf.f = nil
	}
	if err := rf.shiftBackups(); err != nil {
		record.err = err
		return record, rf.keepFileAfterFailedShift()
	}

	f, err := rf.openFile(os.O_CREATE | os.O_RDWR | os.O_TRUNC)
	if err != nil {
		rf.size = 0
		return record, rf.noteOpenFailure(err)
	}
	if rf.budget.backups == 0 {
		// The readers that hold the old file keep their bytes; the name goes.
		_ = os.Remove(rf.rotatingPath())
	}
	rf.f = f
	rf.openErr = nil
	rf.size = 0
	rf.rotateFailedAt = 0
	rf.firstWrite = time.Time{}
	rf.lastWrite = time.Time{}
	rf.headerWritten = false
	return record, rf.writeHeaderLocked()
}

// keepFileAfterFailedShift opens the file that could not move. The append flag
// keeps the lines that are already in it, which a truncating open would drop
// although no backup holds them. It must run with rf.mu held.
func (rf *rotatingFile) keepFileAfterFailedShift() error {
	f, err := rf.openFile(os.O_CREATE | os.O_RDWR | os.O_APPEND)
	if err != nil {
		rf.size = 0
		return rf.noteOpenFailure(err)
	}
	rf.f = f
	rf.openErr = nil
	rf.rotateFailedAt = rf.size
	return nil
}

// noteOpenFailure keeps the error of a failed open and holds the next attempt
// back. It must run with rf.mu held.
func (rf *rotatingFile) noteOpenFailure(err error) error {
	rf.openErr = fmt.Errorf("reopening log file: %w", err)
	rf.retryOpenAt = time.Now().Add(retryOpenInterval)
	return rf.openErr
}

// shiftBackups moves each backup one number up and drops the oldest one. A
// missing backup is normal here, so those moves are best effort: a rotation
// must continue even when one backup cannot move. The move of the current
// file decides the rotation, so its error goes back to the caller. With no
// backup allowed, the current file still moves away, because a truncating
// reopen would change the bytes under an open upload reader.
func (rf *rotatingFile) shiftBackups() error {
	if rf.budget.backups == 0 {
		return rf.moveCurrentFile(rf.rotatingPath())
	}
	for i := rf.budget.backups - 1; i >= 1; i-- {
		_ = rf.renameFile(rf.backupPath(i), rf.backupPath(i+1))
	}
	return rf.moveCurrentFile(rf.backupPath(1))
}

// moveCurrentFile renames the current file. A file that is not there is not
// an error, because a fresh path has nothing to move.
func (rf *rotatingFile) moveCurrentFile(to string) error {
	if err := rf.renameFile(rf.path, to); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// pruneNumberedBackups removes the backups of path above keep. A lowered
// log_max_backups would otherwise leave old files that no reader lists. It
// reads the directory, because the numbers can have gaps. Only a name with an
// exact number after the path goes, because the directory can hold the files
// of another writer.
func pruneNumberedBackups(path string, keep int) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := filepath.Base(path) + "."
	for _, entry := range entries {
		suffix, found := strings.CutPrefix(entry.Name(), prefix)
		if !found {
			continue
		}
		index, err := strconv.Atoi(suffix)
		if err != nil || index <= keep {
			continue
		}
		os.Remove(filepath.Join(dir, entry.Name()))
	}
}

// writeHeaderLocked must run with rf.mu held.
func (rf *rotatingFile) writeHeaderLocked() error {
	if len(rf.header) == 0 {
		return nil
	}
	rf.headerWritten = true
	_, err := rf.writeLocked(rf.header)
	return err
}

// writeLocked appends to the open file and counts the bytes. It must run
// with rf.mu held.
func (rf *rotatingFile) writeLocked(p []byte) (int, error) {
	if rf.f == nil {
		if rf.openErr == nil {
			return 0, errLogFileNotOpen
		}
		if err := rf.retryOpenLocked(); err != nil {
			return 0, err
		}
	}
	n, err := rf.f.Write(p)
	rf.size += int64(n)
	return n, err
}

// retryOpenLocked opens a file again that could not open. A file whose open
// failed once must not stay closed for the life of the process, because the
// cause is often a full disk or a directory that comes back. It must run with
// rf.mu held.
func (rf *rotatingFile) retryOpenLocked() error {
	if time.Now().Before(rf.retryOpenAt) {
		return rf.openErr
	}
	f, err := rf.openFile(os.O_CREATE | os.O_RDWR | os.O_APPEND)
	if err != nil {
		return rf.noteOpenFailure(err)
	}
	rf.f = f
	rf.openErr = nil
	rf.size = 0
	if st, err := f.Stat(); err == nil {
		rf.size = st.Size()
	}
	rf.headerWritten = false
	return rf.writeHeaderLocked()
}

// noteEventWrite keeps the times that the rotation event reports. A header
// is not an event, so it does not move these times.
func (rf *rotatingFile) noteEventWrite() {
	now := time.Now()
	if rf.firstWrite.IsZero() {
		rf.firstWrite = now
	}
	rf.lastWrite = now
}

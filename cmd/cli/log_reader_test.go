package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

const (
	boundedLogTestLineSize  = 100
	boundedLogTestLineCount = 30
	boundedLogTestFileCount = 5
	boundedLogTestBudget    = 10000
)

// boundedLogTestLine returns a line of a fixed size that names its file, so a
// test can tell one part from another.
func boundedLogTestLine(file, line int) []byte {
	head := fmt.Sprintf("file=%d line=%d ", file, line)
	return []byte(head + strings.Repeat("x", boundedLogTestLineSize-len(head)-1) + "\n")
}

// writeBoundedLogTestFiles creates the log files of one stream, oldest first.
func writeBoundedLogTestFiles(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	files := make([]string, 0, boundedLogTestFileCount)
	for file := 0; file < boundedLogTestFileCount; file++ {
		var content bytes.Buffer
		for line := 0; line < boundedLogTestLineCount; line++ {
			content.Write(boundedLogTestLine(file, line))
		}
		path := filepath.Join(dir, fmt.Sprintf("ctrld.log.%d", boundedLogTestFileCount-file))
		if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		files = append(files, path)
	}
	return files
}

func logFilesContent(t *testing.T, files []string) []byte {
	t.Helper()
	var joined []byte
	for _, path := range files {
		joined = append(joined, []byte(rotatingFileTestContent(t, path))...)
	}
	return joined
}

// boundedLogTestFileSize is the size of each file that the bounded reader
// tests select from.
const boundedLogTestFileSize = int64(boundedLogTestLineCount * boundedLogTestLineSize)

// wantTailLine reports the first line that fits in budget, for a budget that
// ends inside the fourth newest file. A cut that lands on a line start keeps
// that line.
func wantTailLine(budget int64) int {
	cut := boundedLogTestFileSize - (budget - 3*boundedLogTestFileSize)
	line := cut / boundedLogTestLineSize
	if cut%boundedLogTestLineSize != 0 {
		line++
	}
	return int(line)
}

// assertTailPart checks that a part starts at a line boundary and that it
// starts with the expected whole line.
func assertTailPart(t *testing.T, part logFilePart, file, line int) {
	t.Helper()
	content := []byte(rotatingFileTestContent(t, part.path))
	if part.offset <= 0 || part.offset >= int64(len(content)) {
		t.Fatalf("offset = %d, want a position inside %s", part.offset, part.path)
	}
	if content[part.offset-1] != '\n' {
		t.Fatalf("offset %d in %s does not follow a newline", part.offset, part.path)
	}
	if want := boundedLogTestLine(file, line); !bytes.HasPrefix(content[part.offset:], want) {
		t.Fatalf("tail of %s starts with %.24q, want %.24q", part.path, content[part.offset:], want)
	}
}

// closeLogParts closes the files of parts that no upload took.
func closeLogParts(parts []logFilePart) {
	for _, part := range parts {
		part.f.Close()
	}
}

// partsSize reports the bytes that the parts hold on disk.
func partsSize(t *testing.T, parts []logFilePart) int64 {
	t.Helper()
	var size int64
	for _, part := range parts {
		content := rotatingFileTestContent(t, part.path)
		size += int64(len(content)) - part.offset
	}
	return size
}

// assertBoundedParts checks the shape that every bounded selection shares:
// the newest three files whole, oldest first, after the tail of the fourth.
func assertBoundedParts(t *testing.T, files []string, parts []logFilePart, tailLine int) {
	t.Helper()
	wantPaths := files[1:]
	if len(parts) != len(wantPaths) {
		t.Fatalf("parts = %d, want %d", len(parts), len(wantPaths))
	}
	for i, part := range parts {
		if part.path != wantPaths[i] {
			t.Fatalf("parts[%d].path = %s, want %s", i, part.path, wantPaths[i])
		}
	}
	assertTailPart(t, parts[0], 1, tailLine)
	for i, part := range parts[1:] {
		if part.offset != 0 {
			t.Fatalf("parts[%d].offset = %d, want the whole file", i+1, part.offset)
		}
	}
}

func Test_boundedLogFiles(t *testing.T) {
	files := writeBoundedLogTestFiles(t)

	t.Run("budget ends at a line boundary", func(t *testing.T) {
		parts := boundedLogFiles(files, boundedLogTestBudget)
		t.Cleanup(func() { closeLogParts(parts) })

		assertBoundedParts(t, files, parts, wantTailLine(boundedLogTestBudget))
		// The cut lands on a line start, so the tail begins at the cut and the
		// parts fill the budget exactly.
		if size := partsSize(t, parts); size != boundedLogTestBudget {
			t.Fatalf("size = %d, want the whole budget of %d", size, boundedLogTestBudget)
		}
	})

	t.Run("budget ends inside a line", func(t *testing.T) {
		const budget = boundedLogTestBudget + boundedLogTestLineSize/2
		parts := boundedLogFiles(files, budget)
		t.Cleanup(func() { closeLogParts(parts) })

		assertBoundedParts(t, files, parts, wantTailLine(budget))
		if size := partsSize(t, parts); size > budget {
			t.Fatalf("size = %d, want at most %d", size, budget)
		}
	})

	t.Run("no budget keeps every file", func(t *testing.T) {
		parts := boundedLogFiles(files, 0)
		t.Cleanup(func() { closeLogParts(parts) })

		if len(parts) != len(files) {
			t.Fatalf("parts = %d, want %d", len(parts), len(files))
		}
		for i, part := range parts {
			if part.path != files[i] || part.offset != 0 {
				t.Fatalf("parts[%d] = %+v, want %s whole", i, part, files[i])
			}
		}
		want := int64(boundedLogTestFileCount) * boundedLogTestFileSize
		if size := partsSize(t, parts); size != want {
			t.Fatalf("size = %d, want %d", size, want)
		}
	})
}

// Test_logReaderDoesNotFollowASymlink covers the one open of the reader. A
// symlink in place of a log file points at a file of another owner, and the
// writer refuses it in the same way.
func Test_logReaderDoesNotFollowASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows opener takes no symlink flag")
	}
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.log")
	if err := os.WriteFile(planted, []byte("planted line\n"), 0600); err != nil {
		t.Fatalf("write the planted file: %v", err)
	}
	path := filepath.Join(dir, "ctrld.log")
	if err := os.Symlink(planted, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	parts := boundedLogFiles([]string{path}, 4)
	if len(parts) != 0 {
		t.Fatalf("the selection opened a symlink: %+v", parts)
	}
	var upload logParts
	upload.addFiles(parts)
	if upload.size != 0 {
		t.Fatalf("the upload holds %d bytes of a symlink, want none", upload.size)
	}
}

// internalLogReaderTestBudget keeps the files small: four lines fill one file,
// so a few writes build the whole backup chain.
var internalLogReaderTestBudget = logBudget{maxSize: 4 * rotatingFileTestLineSize, backups: 2}

const internalLogReaderTestLines = 12

// newTestStreamWriter opens one persisted stream in the temporary home
// directory.
func newTestStreamWriter(t *testing.T, name string) *logWriter {
	t.Helper()
	lw := newLogWriterWithSize(logWriterSize)
	if err := lw.setLogFile(absHomeDir(name), internalLogReaderTestBudget); err != nil {
		t.Fatalf("setLogFile %s: %v", name, err)
	}
	t.Cleanup(lw.closeLogFile)
	return lw
}

// internalLogReaderTestSendBudget holds one debug file and a half, so the
// default upload cuts inside the oldest of the three files.
var internalLogReaderTestSendBudget = internalLogReaderTestBudget.maxSize * 3 / 2

// useTestSendBudget lowers the bound on the debug bytes of one upload, so a
// few small files cross it.
func useTestSendBudget(t *testing.T, budget int64) {
	t.Helper()
	origBudget := logSendDebugBudget
	t.Cleanup(func() { logSendDebugBudget = origBudget })
	logSendDebugBudget = budget
}

// setupInternalLogReaderTest returns a cd mode prog whose debug stream and
// journal stream both hold a full backup chain on disk.
func setupInternalLogReaderTest(t *testing.T) *prog {
	t.Helper()
	origSilent, origCdUID, origHomedir := silent, cdUID, homedir
	t.Cleanup(func() { silent, cdUID, homedir = origSilent, origCdUID, origHomedir })
	captureMainLog(t)
	stubLogHeaderNetworkRead(t, "en9")
	silent, cdUID, homedir = false, "test-uid", t.TempDir()

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.internalLogWriter = newTestStreamWriter(t, logFileName)
	p.internalJournalWriter = newTestStreamWriter(t, journalLogFileName)
	for seq := 1; seq <= internalLogReaderTestLines; seq++ {
		if _, err := p.internalLogWriter.Write(rotatingFileTestLine(1, seq)); err != nil {
			t.Fatalf("write debug line %d: %v", seq, err)
		}
		if _, err := p.internalJournalWriter.Write(rotatingFileTestLine(2, seq)); err != nil {
			t.Fatalf("write journal line %d: %v", seq, err)
		}
	}
	return p
}

// readLogReader reads one upload and checks that the reported size is the
// number of bytes it yields.
func readLogReader(t *testing.T, p *prog, full bool) []byte {
	t.Helper()
	lr, err := p.logReader(full, false)
	if err != nil {
		t.Fatalf("logReader(%v): %v", full, err)
	}
	defer lr.r.Close()
	data, err := io.ReadAll(lr.r)
	if err != nil {
		t.Fatalf("read upload: %v", err)
	}
	if lr.size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", lr.size, len(data))
	}
	return data
}

// splitSendHeader takes the header line off the front of an upload and checks
// that it names this request. It returns the rest of the upload.
func splitSendHeader(t *testing.T, upload []byte, since time.Time) []byte {
	t.Helper()
	end := bytes.IndexByte(upload, '\n')
	if end < 0 {
		t.Fatalf("upload holds no header line: %.64q", upload)
	}
	parsed, _ := parseLogHeader(t, upload[:end+1])
	if parsed.Message != logHeaderMessage {
		t.Fatalf("line 1 of the upload = %q, want %q", parsed.Message, logHeaderMessage)
	}
	if parsed.Trigger != "send" {
		t.Fatalf("trigger = %q, want %q", parsed.Trigger, "send")
	}
	rendered, err := time.Parse(time.RFC3339, parsed.Time)
	if err != nil {
		t.Fatalf("parse header time %q: %v", parsed.Time, err)
	}
	// The header format drops the fraction of a second, so the window starts
	// at the second that holds since.
	if rendered.Before(since.Truncate(time.Second)) || rendered.After(time.Now().Add(time.Second)) {
		t.Fatalf("header time = %s, want a time between %s and now", rendered, since)
	}
	return upload[end+1:]
}

// splitUpload takes the header off an upload and cuts the rest at the log end
// marker, which parts the debug bytes from the journal bytes.
func splitUpload(t *testing.T, upload []byte, since time.Time) (debugPart, journalPart []byte) {
	t.Helper()
	body := splitSendHeader(t, upload, since)
	debugPart, journalPart, found := bytes.Cut(body, []byte(logWriterLogEndMarker))
	if !found {
		t.Fatalf("upload holds no log end marker: %.64q", body)
	}
	return debugPart, journalPart
}

func Test_logRequestPath(t *testing.T) {
	if got := logRequestPath(sendLogsPath, false); got != sendLogsPath {
		t.Fatalf("logRequestPath(%q, false) = %q, want the path itself", sendLogsPath, got)
	}
	want := viewLogsPath + "?full=1"
	if got := logRequestPath(viewLogsPath, true); got != want {
		t.Fatalf("logRequestPath(%q, true) = %q, want %q", viewLogsPath, got, want)
	}
}

func Test_logReader_internalComposition(t *testing.T) {
	p := setupInternalLogReaderTest(t)
	useTestSendBudget(t, internalLogReaderTestSendBudget)

	debugFiles := p.internalLogWriter.rotating().paths()
	journalFiles := p.internalJournalWriter.rotating().paths()
	wantFiles := internalLogReaderTestBudget.backups + 1
	if len(debugFiles) != wantFiles || len(journalFiles) != wantFiles {
		t.Fatalf("files: debug %v, journal %v, want %d of each", debugFiles, journalFiles, wantFiles)
	}
	wholeDebug := logFilesContent(t, debugFiles)
	wholeJournal := logFilesContent(t, journalFiles)

	start := time.Now()
	debugPart, journalPart := splitUpload(t, readLogReader(t, p, false), start)

	if int64(len(debugPart)) > logSendDebugBudget {
		t.Fatalf("debug part = %d bytes, want at most the budget of %d", len(debugPart), logSendDebugBudget)
	}
	if len(debugPart) >= len(wholeDebug) {
		t.Fatalf("debug part = %d bytes, want fewer than the %d bytes of %v", len(debugPart), len(wholeDebug), debugFiles)
	}
	if !bytes.HasSuffix(wholeDebug, debugPart) {
		t.Fatalf("debug part = %.24q, want the newest %d bytes of %v", debugPart, len(debugPart), debugFiles)
	}
	cut := len(wholeDebug) - len(debugPart)
	if wholeDebug[cut-1] != '\n' {
		t.Fatalf("the debug part starts at %d, which does not follow a newline", cut)
	}
	if !bytes.Equal(journalPart, wholeJournal) {
		t.Fatalf("journal part = %d bytes, want the %d bytes of %v", len(journalPart), len(wholeJournal), journalFiles)
	}

	// The full upload lifts the bound, so it holds every debug file.
	fullDebug, fullJournal := splitUpload(t, readLogReader(t, p, true), start)
	if !bytes.Equal(fullDebug, wholeDebug) {
		t.Fatalf("full debug part = %d bytes, want the %d bytes of %v", len(fullDebug), len(wholeDebug), debugFiles)
	}
	if !bytes.Equal(fullJournal, wholeJournal) {
		t.Fatalf("full journal part = %d bytes, want the %d bytes of %v", len(fullJournal), len(wholeJournal), journalFiles)
	}
}

func Test_logReader_logPathComposition(t *testing.T) {
	path := setupLogPathTest(t)
	stubLogHeaderNetworkRead(t, "en9")
	initLoggingWithBackup(false)

	line := strings.Repeat("x", logPathTestLineSize)
	for i := 0; i < logPathTestLineCount; i++ {
		mainLog.Load().Info().Msg(line)
	}

	files := logPathFile.Load().paths()
	if want := []string{path + ".1", path}; !slices.Equal(files, want) {
		t.Fatalf("paths() = %v, want %v", files, want)
	}

	p := &prog{cfg: &cfg}
	p.logger.Store(mainLog.Load())
	start := time.Now()
	got := splitSendHeader(t, readLogReader(t, p, false), start)
	if want := logFilesContent(t, files); !bytes.Equal(got, want) {
		t.Fatalf("upload = %d bytes, want the %d bytes of %v", len(got), len(want), files)
	}
	if bytes.Contains(got, []byte(logWriterLogEndMarker)) {
		t.Fatalf("log_path upload holds the log end marker")
	}
}

// setupMemoryLogReaderTest returns a cd mode prog whose streams keep their
// lines in memory, because no file is open.
func setupMemoryLogReaderTest(t *testing.T) *prog {
	t.Helper()
	origSilent, origCdUID := silent, cdUID
	t.Cleanup(func() { silent, cdUID = origSilent, origCdUID })
	captureMainLog(t)
	stubLogHeaderNetworkRead(t, "en9")
	silent, cdUID = false, "test-uid"

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	p.internalLogWriter = newLogWriterWithSize(logWriterSize)
	p.internalJournalWriter = newLogWriterWithSize(logWriterSize)
	return p
}

func Test_logReader_memoryFallbackStartsWithHeader(t *testing.T) {
	p := setupMemoryLogReaderTest(t)
	debugLine := []byte("debug line\n")
	journalLine := []byte("journal line\n")
	if _, err := p.internalLogWriter.Write(debugLine); err != nil {
		t.Fatalf("write the debug buffer: %v", err)
	}
	if _, err := p.internalJournalWriter.Write(journalLine); err != nil {
		t.Fatalf("write the journal buffer: %v", err)
	}

	start := time.Now()
	got := splitSendHeader(t, readLogReader(t, p, false), start)

	var want []byte
	want = append(want, debugLine...)
	want = append(want, []byte(logWriterLogEndMarker)...)
	want = append(want, journalLine...)
	if !bytes.Equal(got, want) {
		t.Fatalf("upload after the header = %q, want %q", got, want)
	}
}

// useTestHomeDir points the ctrld home directory at a temporary directory, so
// the internal log files of a test never reach the real one.
func useTestHomeDir(t *testing.T) {
	t.Helper()
	origHomedir := homedir
	t.Cleanup(func() { homedir = origHomedir })
	homedir = t.TempDir()
}

// newSeededJournalWriter writes the journal files of an earlier run and
// returns a new writer over them. Its memory buffer is empty, which is what a
// restart finds, so a rule that reads the buffer loses these lines.
func newSeededJournalWriter(t *testing.T, lines int) *logWriter {
	t.Helper()
	previous := newTestStreamWriter(t, journalLogFileName)
	for seq := 1; seq <= lines; seq++ {
		if _, err := previous.Write(rotatingFileTestLine(2, seq)); err != nil {
			t.Fatalf("write journal line %d: %v", seq, err)
		}
	}
	previous.closeLogFile()
	return newTestStreamWriter(t, journalLogFileName)
}

// mixedStreamJournalLines fill two journal files, because four lines fill one.
const mixedStreamJournalLines = 6

func Test_logReader_mixedStreams(t *testing.T) {
	p := setupMemoryLogReaderTest(t)
	useTestHomeDir(t)
	p.internalJournalWriter = newSeededJournalWriter(t, mixedStreamJournalLines)
	debugLine := []byte("debug line\n")
	if _, err := p.internalLogWriter.Write(debugLine); err != nil {
		t.Fatalf("write the debug buffer: %v", err)
	}
	journalFiles := p.internalJournalWriter.rotating().paths()
	if len(journalFiles) != 2 {
		t.Fatalf("journal files = %v, want two", journalFiles)
	}

	start := time.Now()
	got := splitSendHeader(t, readLogReader(t, p, false), start)

	var want []byte
	want = append(want, debugLine...)
	want = append(want, []byte(logWriterLogEndMarker)...)
	want = append(want, logFilesContent(t, journalFiles)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("upload after the header = %d bytes, want the %d bytes of the debug buffer, the marker and %v", len(got), len(want), journalFiles)
	}
}

func Test_logReader_emptyStaysEmpty(t *testing.T) {
	t.Run("internal mode without a line", func(t *testing.T) {
		p := setupMemoryLogReaderTest(t)

		lr, err := p.logReader(false, false)

		if !errors.Is(err, errInternalLogEmpty) {
			t.Fatalf("logReader error = %v, want %v", err, errInternalLogEmpty)
		}
		if lr != nil {
			t.Fatalf("logReader = %+v, want no reader", lr)
		}
	})

	t.Run("internal mode with empty files", func(t *testing.T) {
		p := setupMemoryLogReaderTest(t)
		useTestHomeDir(t)
		p.internalLogWriter = newTestStreamWriter(t, logFileName)
		p.internalJournalWriter = newTestStreamWriter(t, journalLogFileName)

		lr, err := p.logReader(false, false)

		if !errors.Is(err, errInternalLogEmpty) {
			t.Fatalf("logReader error = %v, want %v", err, errInternalLogEmpty)
		}
		if lr != nil {
			t.Fatalf("logReader = %+v, want no reader", lr)
		}
	})

	t.Run("no log_path to read", func(t *testing.T) {
		origSilent, origCdUID := silent, cdUID
		t.Cleanup(func() { silent, cdUID = origSilent, origCdUID })
		stubLogHeaderNetworkRead(t, "en9")
		silent, cdUID = false, ""

		p := &prog{cfg: &ctrld.Config{}}
		p.logger.Store(mainLog.Load())
		lr, err := p.logReader(false, false)
		if err != nil {
			t.Fatalf("logReader: %v", err)
		}
		defer lr.r.Close()

		if lr.size != 0 {
			t.Fatalf("size = %d, want 0 so the handler answers 301", lr.size)
		}
		data, err := io.ReadAll(lr.r)
		if err != nil {
			t.Fatalf("read the upload: %v", err)
		}
		if len(data) != 0 {
			t.Fatalf("upload = %q, want no bytes", data)
		}
	})
}

// Test_boundedLogFilesFixTheSizeAtSelection appends through the real writer
// between the selection and the reader creation. The upload must hold the
// bytes that the selection counted, so the budget holds under a live writer.
func Test_boundedLogFilesFixTheSizeAtSelection(t *testing.T) {
	rf := newTestRotatingFile(t, logBudget{maxSize: 1 << 20, backups: 1})
	if _, err := rf.Write([]byte("one\n")); err != nil {
		t.Fatal(err)
	}
	parts := boundedLogFiles(rf.paths(), 4)
	if _, err := rf.Write([]byte("two\n")); err != nil {
		t.Fatal(err)
	}

	var upload logParts
	upload.addFiles(parts)
	t.Cleanup(upload.close)
	got, err := io.ReadAll(io.MultiReader(upload.readers...))
	if err != nil {
		t.Fatal(err)
	}
	if upload.size != 4 || string(got) != "one\n" {
		t.Fatalf("upload = %q (%d bytes), want %q within the budget of 4", got, upload.size, "one\n")
	}
}

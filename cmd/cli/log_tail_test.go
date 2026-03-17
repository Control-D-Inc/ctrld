package cli

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// logWriter.tailLastLines tests
// =============================================================================

func Test_logWriter_tailLastLines_Empty(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	if got := lw.tailLastLines(10); got != nil {
		t.Fatalf("expected nil for empty buffer, got %q", got)
	}
}

func Test_logWriter_tailLastLines_ZeroLines(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\n"))
	if got := lw.tailLastLines(0); got != nil {
		t.Fatalf("expected nil for n=0, got %q", got)
	}
}

func Test_logWriter_tailLastLines_NegativeLines(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\n"))
	if got := lw.tailLastLines(-1); got != nil {
		t.Fatalf("expected nil for n=-1, got %q", got)
	}
}

func Test_logWriter_tailLastLines_FewerThanN(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\n"))
	got := string(lw.tailLastLines(10))
	want := "line1\nline2\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_logWriter_tailLastLines_ExactN(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\nline3\n"))
	got := string(lw.tailLastLines(3))
	want := "line1\nline2\nline3\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_logWriter_tailLastLines_MoreThanN(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\nline3\nline4\nline5\n"))
	got := string(lw.tailLastLines(2))
	want := "line4\nline5\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_logWriter_tailLastLines_NoTrailingNewline(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("line1\nline2\nline3"))
	// Without trailing newline, "line3" is a partial line.
	// Asking for 1 line returns the last newline-terminated line plus the partial.
	got := string(lw.tailLastLines(1))
	want := "line2\nline3"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_logWriter_tailLastLines_SingleLineNoNewline(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("only line"))
	got := string(lw.tailLastLines(5))
	want := "only line"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_logWriter_tailLastLines_SingleLineWithNewline(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	lw.Write([]byte("only line\n"))
	got := string(lw.tailLastLines(1))
	want := "only line\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// =============================================================================
// logWriter.Subscribe tests
// =============================================================================

func Test_logWriter_Subscribe_Basic(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	ch, unsub := lw.Subscribe()
	defer unsub()

	msg := []byte("hello world\n")
	lw.Write(msg)

	select {
	case got := <-ch:
		if string(got) != string(msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscriber data")
	}
}

func Test_logWriter_Subscribe_MultipleSubscribers(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	ch1, unsub1 := lw.Subscribe()
	defer unsub1()
	ch2, unsub2 := lw.Subscribe()
	defer unsub2()

	msg := []byte("broadcast\n")
	lw.Write(msg)

	for i, ch := range []<-chan []byte{ch1, ch2} {
		select {
		case got := <-ch:
			if string(got) != string(msg) {
				t.Fatalf("subscriber %d: got %q, want %q", i, got, msg)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out", i)
		}
	}
}

func Test_logWriter_Subscribe_Unsubscribe(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	ch, unsub := lw.Subscribe()

	// Verify subscribed.
	lw.Write([]byte("before unsub\n"))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out before unsub")
	}

	unsub()

	// Channel should be closed after unsub.
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}

	// Verify subscriber list is empty.
	lw.mu.Lock()
	count := len(lw.subscribers)
	lw.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 subscribers after unsub, got %d", count)
	}
}

func Test_logWriter_Subscribe_UnsubscribeIdempotent(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	_, unsub := lw.Subscribe()
	unsub()
	// Second unsub should not panic.
	unsub()
}

func Test_logWriter_Subscribe_SlowSubscriberDropped(t *testing.T) {
	lw := newLogWriterWithSize(4096)
	ch, unsub := lw.Subscribe()
	defer unsub()

	// Fill the subscriber channel (buffer size is 256).
	for i := 0; i < 300; i++ {
		lw.Write([]byte("msg\n"))
	}

	// Should have 256 buffered messages, rest dropped.
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done
		}
	}
done:
	if count != 256 {
		t.Fatalf("expected 256 buffered messages, got %d", count)
	}
}

func Test_logWriter_Subscribe_ConcurrentWriteAndRead(t *testing.T) {
	lw := newLogWriterWithSize(64 * 1024)
	ch, unsub := lw.Subscribe()
	defer unsub()

	const numWrites = 100
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numWrites; i++ {
			lw.Write([]byte("concurrent write\n"))
		}
	}()

	received := 0
	timeout := time.After(5 * time.Second)
	for received < numWrites {
		select {
		case <-ch:
			received++
		case <-timeout:
			t.Fatalf("timed out after receiving %d/%d messages", received, numWrites)
		}
	}
	wg.Wait()
}

// =============================================================================
// tailFileLastLines tests
// =============================================================================

func writeTempFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tail-test-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	return f
}

func Test_tailFileLastLines_Empty(t *testing.T) {
	f := writeTempFile(t, "")
	defer f.Close()
	if got := tailFileLastLines(f, 10); got != nil {
		t.Fatalf("expected nil for empty file, got %q", got)
	}
}

func Test_tailFileLastLines_FewerThanN(t *testing.T) {
	f := writeTempFile(t, "line1\nline2\n")
	defer f.Close()
	got := string(tailFileLastLines(f, 10))
	want := "line1\nline2\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_tailFileLastLines_ExactN(t *testing.T) {
	f := writeTempFile(t, "a\nb\nc\n")
	defer f.Close()
	got := string(tailFileLastLines(f, 3))
	want := "a\nb\nc\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_tailFileLastLines_MoreThanN(t *testing.T) {
	f := writeTempFile(t, "line1\nline2\nline3\nline4\nline5\n")
	defer f.Close()
	got := string(tailFileLastLines(f, 2))
	want := "line4\nline5\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_tailFileLastLines_NoTrailingNewline(t *testing.T) {
	f := writeTempFile(t, "line1\nline2\nline3")
	defer f.Close()
	// Without trailing newline, partial last line comes with the previous line.
	got := string(tailFileLastLines(f, 1))
	want := "line2\nline3"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func Test_tailFileLastLines_LargerThanChunk(t *testing.T) {
	// Build content larger than the 4096 chunk size to exercise multi-chunk reads.
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString(strings.Repeat("x", 50))
		sb.WriteByte('\n')
	}
	f := writeTempFile(t, sb.String())
	defer f.Close()
	got := string(tailFileLastLines(f, 3))
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), got)
	}
	expectedLine := strings.Repeat("x", 50)
	for _, line := range lines {
		if line != expectedLine {
			t.Fatalf("unexpected line content: %q", line)
		}
	}
}

func Test_tailFileLastLines_SeeksToEnd(t *testing.T) {
	f := writeTempFile(t, "line1\nline2\nline3\n")
	defer f.Close()
	tailFileLastLines(f, 1)

	// After tailFileLastLines, file position should be at the end.
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if pos != stat.Size() {
		t.Fatalf("expected file position at end (%d), got %d", stat.Size(), pos)
	}
}

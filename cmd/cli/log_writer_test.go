package cli

import (
	"strings"
	"sync"
	"testing"
)

func Test_logWriter_Write(t *testing.T) {
	size := 64 * 1024
	lw := &logWriter{size: size}
	lw.buf.Grow(lw.size)
	data := strings.Repeat("A", size)
	lw.Write([]byte(data))
	if lw.buf.String() != data {
		t.Fatalf("unexpected buf content: %v", lw.buf.String())
	}
	newData := "B"
	halfData := strings.Repeat("A", len(data)/2) + logStartEndMarker
	lw.Write([]byte(newData))
	if lw.buf.String() != halfData+newData {
		t.Fatalf("unexpected new buf content: %v", lw.buf.String())
	}

	bigData := strings.Repeat("B", 256*1024)
	expected := halfData + strings.Repeat("B", 16*1024)
	lw.Write([]byte(bigData))
	if lw.buf.String() != expected {
		t.Fatalf("unexpected big buf content: %v", lw.buf.String())
	}
}

func Test_logWriter_ConcurrentWrite(t *testing.T) {
	size := 64 * 1024
	lw := &logWriter{size: size}
	n := 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			lw.Write([]byte(strings.Repeat("A", i)))
		}()
	}
	wg.Wait()
	if lw.buf.Len() > lw.size {
		t.Fatalf("unexpected buf size: %v, content: %q", lw.buf.Len(), lw.buf.String())
	}
}

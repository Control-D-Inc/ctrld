package cli

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

// journalMarker is the serialized form of the journal field in a JSON line.
var journalMarker = []byte(`"` + journalField + `":true`)

// hasJournalMarker reports whether a log line carries the journal field. A
// JSON line writes the field without a space, a console line with one.
func hasJournalMarker(line string) bool {
	return strings.Contains(line, string(journalMarker)) || strings.Contains(line, `"`+journalField+`": true`)
}

// newTestJSONLogger writes one JSON object for each line to every writer, at
// debug level, with the field names of the journal. A test parses the lines
// back, so the encoder must be the JSON one.
func newTestJSONLogger(writers ...io.Writer) *ctrld.Logger {
	cores := make([]zapcore.Core, 0, len(writers))
	for _, w := range writers {
		cores = append(cores, zapcore.NewCore(newJournalEncoder(), zapcore.AddSync(w), zapcore.DebugLevel))
	}
	return &ctrld.Logger{Logger: zap.New(zapcore.NewTee(cores...))}
}

// captureJSONMainLog swaps mainLog for a JSON logger that writes into a
// buffer at debug level and puts the old logger back when the test ends. The
// JSON form lets a test parse the lines it captured. It swaps a global, so
// no test of this package runs in parallel.
func captureJSONMainLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := mainLog.Load()
	mainLog.Store(newTestJSONLogger(buf))
	t.Cleanup(func() { mainLog.Store(old) })
	return buf
}

// parseLogLineFields returns the fields of one log line. A JSON line is one
// object. A console line of the debug stream ends with its fields as one
// object after the last tab.
func parseLogLineFields(t *testing.T, line string) map[string]json.RawMessage {
	t.Helper()
	line = strings.TrimSpace(line)
	object := line
	if !strings.HasPrefix(line, "{") {
		index := strings.LastIndex(line, "\t{")
		if index < 0 {
			t.Fatalf("log line holds no fields: %q", line)
		}
		object = line[index+1:]
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(object), &fields); err != nil {
		t.Fatalf("parse fields of %q: %v", line, err)
	}
	return fields
}

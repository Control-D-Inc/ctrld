package cli

import (
	"bytes"
	"io"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
)

// journalField marks an event for the retained journal stream. Both packages
// share the name, so one writer keeps the lines of both.
const journalField = ctrld.JournalField

// journalMarker is the serialized form of the journal field. The journal
// writer keeps a line below warn level only when the line contains it.
var journalMarker = []byte(`"` + journalField + `":true`)

// journal marks an event for the retained journal stream. The event keeps
// its own level, so an info event stays info on the console.
func journal(e *zerolog.Event) *zerolog.Event {
	return ctrld.Journal(e)
}

// journalLevelWriter passes on the lines that the journal keeps and drops the
// rest, so the journal holds a small history that survives a restart.
type journalLevelWriter struct {
	w io.Writer
}

var _ zerolog.LevelWriter = (*journalLevelWriter)(nil)

func newJournalLevelWriter(w io.Writer) *journalLevelWriter {
	return &journalLevelWriter{w: w}
}

// WriteLevel reads the level first, because a compare costs less than a scan
// of the serialized line.
func (j *journalLevelWriter) WriteLevel(l zerolog.Level, p []byte) (int, error) {
	if l < zerolog.WarnLevel && !bytes.Contains(p, journalMarker) {
		// A dropped line reports a full write, because zerolog.MultiLevelWriter
		// turns a short write into an error for the whole group of writers.
		return len(p), nil
	}
	if _, err := j.w.Write(p); err != nil {
		return 0, err
	}
	// The memory stream cuts a line that does not fit in it, and a short write
	// is an error for the whole group of writers.
	return len(p), nil
}

// Write has no level to read, so the marker alone decides. Every level below
// warn takes that path.
func (j *journalLevelWriter) Write(p []byte) (int, error) {
	return j.WriteLevel(zerolog.DebugLevel, p)
}

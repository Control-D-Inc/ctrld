package cli

import (
	"bytes"
	"io"
	"regexp"

	"github.com/rs/zerolog"
)

// journalField marks an event for the retained journal stream.
const journalField = "journal"

// journalMarker is the serialized form of the journal field. The journal
// writer keeps a line below warn level only when the line contains it.
var journalMarker = []byte(`"` + journalField + `":true`)

// retainedURLPath matches the part of a URL that follows the host. The class
// stops the match at the characters that end a value inside a JSON line.
var retainedURLPath = regexp.MustCompile(`(https?://[^/?"\\\s]+)[/?][^"\\\s]*`)

// redactRetainedLine strips the secrets of one line that the journal keeps.
// Support downloads the journal whole, and any error text can carry a DoH URL
// with the resolver path and the packed query of the user.
func redactRetainedLine(p []byte) []byte {
	stripped := retainedURLPath.ReplaceAll(p, []byte(`${1}/[redacted]`))
	return []byte(redactSecrets(string(stripped), provisionSecrets()...))
}

// journal marks an event for the retained journal stream. The event keeps
// its own level, so an info event stays info on the console.
func journal(e *zerolog.Event) *zerolog.Event {
	return e.Bool(journalField, true)
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
	if _, err := j.w.Write(redactRetainedLine(p)); err != nil {
		return 0, err
	}
	// The redacted line is shorter than the line the logger handed over, and a
	// short write is an error for the whole group of writers.
	return len(p), nil
}

// Write has no level to read, so the marker alone decides. Every level below
// warn takes that path.
func (j *journalLevelWriter) Write(p []byte) (int, error) {
	return j.WriteLevel(zerolog.DebugLevel, p)
}

package cli

import (
	"bytes"
	"io"
	"regexp"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// journalField marks an event for the retained journal stream. Both packages
// share the name, so one writer keeps the lines of both.
const journalField = ctrld.JournalField

// journalMarker is the serialized form of the journal field. The journal
// writer keeps a line below warn level only when the line contains it.
var journalMarker = []byte(`"` + journalField + `":true`)

// retainedURLPath matches the part of a URL that follows the host, for every
// scheme: a DoH, DoH3, or DoQ endpoint carries its token in the path. The
// class stops the match at the characters that end a value inside a JSON line.
var retainedURLPath = regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^/?"\\\s]+)[/?][^"\\\s]*`)

// retainedControlDHost matches a Control D resolver host. The first label of
// the host is the resolver ID, which a DoT or DoQ endpoint carries in place of
// a path.
var retainedControlDHost = regexp.MustCompile(`([A-Za-z0-9-]+)(\.dns\.controld\.(?:com|dev))`)

// redactRetainedLine strips the secrets of one line that the journal keeps.
// Support downloads the journal whole, and any error text can carry a DoH URL
// with the resolver path and the packed query of the user.
func redactRetainedLine(p []byte) []byte {
	stripped := retainedURLPath.ReplaceAll(p, []byte(`${1}/[redacted]`))
	stripped = retainedControlDHost.ReplaceAll(stripped, []byte(`[redacted]${2}`))
	return []byte(redactSecrets(string(stripped), journalSecrets()...))
}

// journalSecrets names the values that no retained line may hold. The client
// ID stays out: it is a device label, not a secret. redactSecrets drops the
// values that are too short to redact.
func journalSecrets() []string {
	uid, _ := controld.ParseRawUID(cdUID)
	return []string{cdUID, cdOrg, uid}
}

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

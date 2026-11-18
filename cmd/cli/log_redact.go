package cli

import (
	"bytes"
	"io"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"

	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// redactingSink is the one redaction step of the logger. Each core of the
// logger writes through it, so each line passes redactLogLine before any sink
// gets it: the console, the log_path file, the debug stream, and the journal.
// A user can share each of them, and a service keeps its console output on
// disk, so a sink with no redaction leaks every secret that a message ever
// carries.
type redactingSink struct {
	w zapcore.WriteSyncer
}

// newLogSink puts the redaction step in front of w. Each core of the logger
// takes its writer from here.
func newLogSink(w io.Writer) zapcore.WriteSyncer {
	return redactingSink{w: zapcore.AddSync(w)}
}

func (r redactingSink) Write(p []byte) (int, error) {
	if _, err := r.w.Write(redactLogLine(p)); err != nil {
		return 0, err
	}
	// The redacted line can differ in length from the line that the logger
	// handed over, and a short write is an error for the logger.
	return len(p), nil
}

func (r redactingSink) Sync() error {
	return r.w.Sync()
}

// logURL matches a URL of every scheme: a DoH, DoH3, or DoQ endpoint carries
// its token in the path. The part after the scheme holds the userinfo and the
// host, and a path, a query, or a fragment can follow. A quote, a backslash,
// or whitespace ends a value inside a JSON line, so it ends the URL. A JSON
// escape inside the path does not, except an escaped quote and escaped
// whitespace, which end the URL in the text.
var logURL = regexp.MustCompile(`(?i:[a-z][a-z0-9+.-]*)://[^/?#"\\\s]+(?:[/?#](?:[^"\\\s]|\\[^"nrt\s])*)?`)

// logControlDHost matches a Control D resolver host. The first label of
// the host is the resolver ID, which a DoT or DoQ endpoint carries in place of
// a path. A resolver can change the letter case of a name (DNS 0x20).
var logControlDHost = regexp.MustCompile(`(?i)([a-z0-9-]+)(\.dns\.controld\.(?:com|dev))`)

// The literal parts of the patterns. A regex scan costs more than the line
// that the logger formats, so each pattern runs only on a line that holds its
// literal part.
var (
	urlSchemeSeparator = []byte("://")
	controlDHostSuffix = []byte(".dns.controld.")
	redactedMark       = []byte("[redacted]")
)

// lowerLines lends the buffer for the lower-case copy of a line, so the
// redaction of a line with no secret costs no allocation.
var lowerLines = sync.Pool{New: func() any { return new([]byte) }}

// maxPooledLineBytes keeps a large copy, such as the one of carried log
// lines, out of the pool.
const maxPooledLineBytes = 64 << 10

// redactLogLine strips the secrets of one log line. Any error text can
// carry a DoH URL with the resolver path and the packed query of the user, or
// the URL of an API request with the resolver UID in its query. A resolver
// can change the letter case of a name, so the host and the stored secrets
// match in every letter case. The result can be p itself, so a caller must
// not keep it after the write.
func redactLogLine(p []byte) []byte {
	pooled := lowerLines.Get().(*[]byte)
	lower := appendASCIILower((*pooled)[:0], p)
	changed := false
	if bytes.Contains(p, urlSchemeSeparator) {
		p = logURL.ReplaceAllFunc(p, redactURLPath)
		changed = true
	}
	if bytes.Contains(lower, controlDHostSuffix) {
		p = logControlDHost.ReplaceAll(p, []byte(`[redacted]${2}`))
		changed = true
	}
	if changed {
		lower = appendASCIILower(lower[:0], p)
	}
	for _, secret := range logSecrets() {
		if !bytes.Contains(lower, secret) {
			continue
		}
		p = replaceFolded(p, lower, secret)
		lower = appendASCIILower(lower[:0], p)
	}
	if cap(lower) <= maxPooledLineBytes {
		*pooled = lower
		lowerLines.Put(pooled)
	}
	return p
}

// appendASCIILower appends p to dst with each ASCII letter in lower case.
// Each byte keeps its offset, so an index into the copy is an index into p.
func appendASCIILower(dst, p []byte) []byte {
	start := len(dst)
	dst = slices.Grow(dst, len(p))[:start+len(p)]
	for i, c := range p {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[start+i] = c
	}
	return dst
}

// replaceFolded replaces each match of secret with the redaction mark. lower
// is p in lower case, and secret is in lower case, so a match in lower is a
// match in p in some letter case.
func replaceFolded(p, lower, secret []byte) []byte {
	redacted := make([]byte, 0, len(p))
	start := 0
	for {
		i := bytes.Index(lower[start:], secret)
		if i < 0 {
			return append(redacted, p[start:]...)
		}
		redacted = append(redacted, p[start:start+i]...)
		redacted = append(redacted, redactedMark...)
		start += i + len(secret)
	}
}

// redactURLPath keeps the scheme and the host of a URL that logURL matched.
// It drops the userinfo, and puts the redaction mark in place of the path,
// the query, and the fragment.
func redactURLPath(url []byte) []byte {
	authorityStart := bytes.Index(url, urlSchemeSeparator) + len(urlSchemeSeparator)
	authorityEnd := len(url)
	if i := bytes.IndexAny(url[authorityStart:], "/?#"); i >= 0 {
		authorityEnd = authorityStart + i
	}
	hostStart := authorityStart
	if at := bytes.LastIndexByte(url[authorityStart:authorityEnd], '@'); at >= 0 {
		hostStart = authorityStart + at + 1
	}
	if hostStart == authorityStart && authorityEnd == len(url) {
		return url
	}
	redacted := make([]byte, 0, authorityEnd+len("/[redacted]"))
	redacted = append(redacted, url[:authorityStart]...)
	redacted = append(redacted, url[hostStart:authorityEnd]...)
	if authorityEnd < len(url) {
		redacted = append(redacted, "/[redacted]"...)
	}
	return redacted
}

// logSecretValues holds the values that no log line may hold, in lower case.
// The log writers run on any thread, and a start writes cdUID and cdOrg on
// its own thread, so the writers read this copy and never the globals. The
// copy holds bytes, because the writers compare it with every line, and a
// conversion of a long value on each line costs an allocation.
var logSecretValues atomic.Pointer[[][]byte]

// storeLogSecrets copies cdUID and cdOrg into logSecretValues. Call
// it after each change of either value. The client ID stays out: it is a
// device label, not a secret. A value shorter than redactSecretMinLen stays
// out too.
func storeLogSecrets() {
	values := []string{cdUID, cdOrg}
	// With no client ID, the UID part is cdUID itself, and a second copy
	// costs a second scan of every line.
	if uid, _ := controld.ParseRawUID(cdUID); uid != cdUID {
		values = append(values, uid)
	}
	secrets := make([][]byte, 0, len(values))
	for _, secret := range values {
		if len(secret) >= redactSecretMinLen {
			secrets = append(secrets, appendASCIILower(nil, []byte(secret)))
		}
	}
	logSecretValues.Store(&secrets)
}

// setCdUID sets cdUID and the copy that the log writers read.
func setCdUID(uid string) {
	cdUID = uid
	storeLogSecrets()
}

// logSecrets returns the values that no log line may hold.
func logSecrets() [][]byte {
	if secrets := logSecretValues.Load(); secrets != nil {
		return *secrets
	}
	return nil
}

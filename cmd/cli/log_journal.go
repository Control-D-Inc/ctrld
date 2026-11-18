package cli

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Control-D-Inc/ctrld"
)

// journalField marks an event for the retained journal stream. Both packages
// share the name, so one core keeps the lines of both.
const journalField = ctrld.JournalField

// journal marks an event for the retained journal stream. The event keeps
// its own level, so an info event stays info on the console.
func journal(e *ctrld.LogEvent) *ctrld.LogEvent {
	return ctrld.Journal(e)
}

// journalTimeLayout is the time format of a journal line: RFC 3339 with
// milliseconds.
const journalTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// newJournalEncoder is the encoder of the journal and of the header line: one
// JSON object for each line, with the field names that the log tools read.
// The debug stream keeps its console layout for the operator who reads it on
// the host.
func newJournalEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(journalTimeLayout)
	encoderConfig.LevelKey = "level"
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.MessageKey = "message"
	return zapcore.NewJSONEncoder(encoderConfig)
}

// journalCore writes the lines that the journal keeps and drops the rest, so
// the journal holds a small history that survives a restart. It keeps every
// line at warn level or above, and every line that carries the journal field.
// Notice shares its level value with warn, so a notice line stays too.
type journalCore struct {
	zapcore.LevelEnabler
	encoder zapcore.Encoder
	out     zapcore.WriteSyncer
	// marked is set when With bound the journal field, so every line of that
	// logger belongs to the journal.
	marked bool
}

var _ zapcore.Core = (*journalCore)(nil)

// newJournalCore makes the core of the journal stream. It accepts every level,
// because a debug line with the journal field belongs to the journal too.
func newJournalCore(w io.Writer) *journalCore {
	return &journalCore{
		LevelEnabler: zapcore.DebugLevel,
		encoder:      newJournalEncoder(),
		out:          newLogSink(w),
	}
}

func (c *journalCore) With(fields []zapcore.Field) zapcore.Core {
	clone := &journalCore{
		LevelEnabler: c.LevelEnabler,
		encoder:      c.encoder.Clone(),
		out:          c.out,
		marked:       c.marked || hasJournalField(fields),
	}
	for _, field := range fields {
		field.AddTo(clone.encoder)
	}
	return clone
}

func (c *journalCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

// Write keeps or drops one line. A dropped line is not an error.
func (c *journalCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if !c.retains(entry, fields) {
		return nil
	}
	buf, err := c.encoder.EncodeEntry(entry, fields)
	if err != nil {
		return err
	}
	defer buf.Free()
	// c.out is the redaction step of the logger.
	_, err = c.out.Write(buf.Bytes())
	return err
}

func (c *journalCore) Sync() error {
	return c.out.Sync()
}

// retains reads the level first, because a compare costs less than a scan of
// the fields.
func (c *journalCore) retains(entry zapcore.Entry, fields []zapcore.Field) bool {
	return c.marked || entry.Level >= zapcore.WarnLevel || hasJournalField(fields)
}

// hasJournalField reports whether fields carry the journal marker.
func hasJournalField(fields []zapcore.Field) bool {
	for _, field := range fields {
		if field.Key == journalField && field.Type == zapcore.BoolType && field.Integer == 1 {
			return true
		}
	}
	return false
}

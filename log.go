package ctrld

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// ProxyLog emits the log record for proxy operations.
// The caller should set it only once.
// DEPRECATED: use ProxyLogger instead.
var ProxyLog = zerolog.New(io.Discard)

// ProxyLogger emits the log record for proxy operations.
var ProxyLogger atomic.Pointer[zerolog.Logger]

// ReqIdCtxKey is the context.Context key for a request id.
type ReqIdCtxKey struct{}

// Log emits the logs for a particular zerolog event.
// The request id associated with the context will be included if presents.
func Log(ctx context.Context, e *zerolog.Event, format string, v ...any) {
	id, ok := ctx.Value(ReqIdCtxKey{}).(string)
	if !ok {
		e.Msgf(format, v...)
		return
	}
	e.MsgFunc(func() string {
		return fmt.Sprintf("[%s] %s", id, fmt.Sprintf(format, v...))
	})
}

// JournalField marks an event for the retained journal stream.
const JournalField = "journal"

// Journal marks an event for the retained journal stream. The journal writer
// keeps every line that carries the field, whatever the level of the line is.
func Journal(e *zerolog.Event) *zerolog.Event {
	return e.Bool(JournalField, true)
}

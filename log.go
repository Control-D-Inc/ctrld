package ctrld

import (
	"context"
	"fmt"
	"io"

	"github.com/rs/zerolog"
)

// ProxyLog emits the log record for proxy operations.
// The caller should set it only once.
var ProxyLog = zerolog.New(io.Discard)

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

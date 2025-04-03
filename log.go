package ctrld

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

// LoggerCtxKey is the context.Context key for a logger.
type LoggerCtxKey struct{}

// LoggerCtx returns a context.Context with LoggerCtxKey set.
func LoggerCtx(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, LoggerCtxKey{}, l)
}

// A Logger provides fast, leveled, structured logging.
type Logger struct {
	*zerolog.Logger
}

var noOpZeroLogger = zerolog.Nop()

// NopLogger returns a logger which all operation are no-op.
var NopLogger = &Logger{&noOpZeroLogger}

// LoggerFromCtx returns the logger associated with given ctx.
//
// If there's no logger, a no-op logger will be returned.
func LoggerFromCtx(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(LoggerCtxKey{}).(*Logger); ok && logger != nil {
		return logger
	}
	return NopLogger
}

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

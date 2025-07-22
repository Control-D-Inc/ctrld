package ctrld

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Custom log level for NOTICE (between INFO and WARN)
// DEBUG = -1, INFO = 0, WARN = 1, ERROR = 2, FATAL = 3
// Since there's no integer between INFO (0) and WARN (1), we'll use the same value as WARN
// but handle NOTICE specially in the encoder to display it differently.
// Note: NOTICE and WARN share the same numeric value (1), so they will both display as "NOTICE"
// when using the custom encoder. This is the intended behavior for visual distinction.
const NoticeLevel = zapcore.Level(zapcore.WarnLevel) // Same value as WARN, but handled specially

// LoggerCtxKey is the context.Context key for a logger.
type LoggerCtxKey struct{}

// LoggerCtx returns a context.Context with LoggerCtxKey set.
func LoggerCtx(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, LoggerCtxKey{}, l)
}

// A Logger provides fast, leveled, structured logging.
type Logger struct {
	*zap.Logger
}

var noOpZapLogger = zap.NewNop()

// NopLogger returns a logger which all operation are no-op.
var NopLogger = &Logger{noOpZapLogger}

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

// LogEvent represents a logging event with structured fields
type LogEvent struct {
	logger *zap.Logger
	level  zapcore.Level
	fields []zap.Field
}

// Msg logs the message with the collected fields
func (e *LogEvent) Msg(msg string) {
	e.logger.Check(e.level, msg).Write(e.fields...)
}

// Msgf logs a formatted message with the collected fields
func (e *LogEvent) Msgf(format string, v ...any) {
	e.Msg(fmt.Sprintf(format, v...))
}

// MsgFunc logs a message from a function with the collected fields
func (e *LogEvent) MsgFunc(fn func() string) {
	e.Msg(fn())
}

// Str adds a string field to the event
func (e *LogEvent) Str(key, val string) *LogEvent {
	e.fields = append(e.fields, zap.String(key, val))
	return e
}

// Int adds an integer field to the event
func (e *LogEvent) Int(key string, val int) *LogEvent {
	e.fields = append(e.fields, zap.Int(key, val))
	return e
}

// Int64 adds an int64 field to the event
func (e *LogEvent) Int64(key string, val int64) *LogEvent {
	e.fields = append(e.fields, zap.Int64(key, val))
	return e
}

// Err adds an error field to the event
func (e *LogEvent) Err(err error) *LogEvent {
	if err != nil {
		e.fields = append(e.fields, zap.Error(err))
	}
	return e
}

// Bool adds a boolean field to the event
func (e *LogEvent) Bool(key string, val bool) *LogEvent {
	e.fields = append(e.fields, zap.Bool(key, val))
	return e
}

// Interface adds an interface field to the event
func (e *LogEvent) Interface(key string, val interface{}) *LogEvent {
	e.fields = append(e.fields, zap.Any(key, val))
	return e
}

// Any adds an interface field to the event (alias for Interface)
func (e *LogEvent) Any(key string, val interface{}) *LogEvent {
	return e.Interface(key, val)
}

// Strs adds a string slice field to the event
func (e *LogEvent) Strs(key string, vals []string) *LogEvent {
	e.fields = append(e.fields, zap.Strings(key, vals))
	return e
}

// Log emits the logs for a particular logging event.
// The request id associated with the context will be included if presents.
func Log(ctx context.Context, e *LogEvent, format string, v ...any) {
	id, ok := ctx.Value(ReqIdCtxKey{}).(string)
	if !ok {
		e.Msgf(format, v...)
		return
	}
	e.MsgFunc(func() string {
		return fmt.Sprintf("[%s] %s", id, fmt.Sprintf(format, v...))
	})
}

// Logger methods that mimic zerolog API
func (l *Logger) Debug() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  zapcore.DebugLevel,
		fields: []zap.Field{},
	}
}

func (l *Logger) Info() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  zapcore.InfoLevel,
		fields: []zap.Field{},
	}
}

func (l *Logger) Warn() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  zapcore.WarnLevel,
		fields: []zap.Field{},
	}
}

func (l *Logger) Error() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  zapcore.ErrorLevel,
		fields: []zap.Field{},
	}
}

func (l *Logger) Fatal() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  zapcore.FatalLevel,
		fields: []zap.Field{},
	}
}

func (l *Logger) Notice() *LogEvent {
	return &LogEvent{
		logger: l.Logger,
		level:  NoticeLevel, // Custom NOTICE level between INFO and WARN
		fields: []zap.Field{},
	}
}

// With returns a logger with additional fields
func (l *Logger) With() *Logger {
	return l
}

// Str adds a string field to the logger
func (l *Logger) Str(key, val string) *Logger {
	// Create a new logger with the field added
	newLogger := l.Logger.With(zap.String(key, val))
	return &Logger{newLogger}
}

// Err adds an error field to the logger
func (l *Logger) Err(err error) *Logger {
	// Create a new logger with the error field added
	newLogger := l.Logger.With(zap.Error(err))
	return &Logger{newLogger}
}

// Any adds an interface field to the logger
func (l *Logger) Any(key string, val interface{}) *Logger {
	// Create a new logger with the field added
	newLogger := l.Logger.With(zap.Any(key, val))
	return &Logger{newLogger}
}

// Bool adds a boolean field to the logger
func (l *Logger) Bool(key string, val bool) *Logger {
	// Create a new logger with the field added
	newLogger := l.Logger.With(zap.Bool(key, val))
	return &Logger{newLogger}
}

// Msgf logs a formatted message at info level
func (l *Logger) Msgf(format string, v ...any) {
	l.Info().Msgf(format, v...)
}

// Msg logs a message at info level
func (l *Logger) Msg(msg string) {
	l.Info().Msg(msg)
}

// Output returns a logger with the specified output
func (l *Logger) Output(w io.Writer) *Logger {
	// Create a new zap logger with the writer
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	core := zapcore.NewCore(encoder, zapcore.AddSync(w), zapcore.InfoLevel)
	newLogger := zap.New(core)
	return &Logger{newLogger}
}

// GetLogger returns the underlying logger
func (l *Logger) GetLogger() *Logger {
	return l
}

// Write implements io.Writer to allow direct writing to the logger
func (l *Logger) Write(p []byte) (n int, err error) {
	l.Info().Msg(string(p))
	return len(p), nil
}

// Printf logs a formatted message at info level
func (l *Logger) Printf(format string, v ...any) {
	l.Info().Msgf(format, v...)
}

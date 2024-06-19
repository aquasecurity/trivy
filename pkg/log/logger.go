package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/samber/lo"
)

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
	LevelFatal = slog.Level(12)
)

// Logger is an alias of slog.Logger
type Logger = slog.Logger

// New creates a new Logger with the given non-nil Handler.
func New(h slog.Handler) *Logger {
	return slog.New(h)
}

// InitLogger initialize the logger variable
func InitLogger(debug, disable bool) {
	level := lo.Ternary(debug, slog.LevelDebug, slog.LevelInfo)
	out := lo.Ternary(disable, io.Discard, io.Writer(os.Stderr))
	slog.SetDefault(New(NewHandler(out, &Options{Level: level})))
}

var (
	// With calls [Logger.With] on the default logger.
	With = slog.With

	SetDefault = slog.SetDefault

	Debug        = slog.Debug
	DebugContext = slog.DebugContext
	Info         = slog.Info
	InfoContext  = slog.InfoContext
	Warn         = slog.Warn
	WarnContext  = slog.WarnContext
	Error        = slog.Error
	ErrorContext = slog.ErrorContext
)

// WithPrefix calls [Logger.With] with the prefix on the default logger.
//
// Note: If WithPrefix is called within init() or during global variable
// initialization, it will use the default logger of log/slog package
// before Trivy's logger is set up. In such cases, it's recommended to pass the prefix
// via WithContextPrefix to ensure the correct logger is used.
func WithPrefix(prefix string) *Logger {
	return slog.Default().With(Prefix(prefix))
}

func Debugf(format string, args ...any) { slog.Default().Debug(fmt.Sprintf(format, args...)) }
func Infof(format string, args ...any)  { slog.Default().Info(fmt.Sprintf(format, args...)) }
func Warnf(format string, args ...any)  { slog.Default().Warn(fmt.Sprintf(format, args...)) }
func Errorf(format string, args ...any) { slog.Default().Error(fmt.Sprintf(format, args...)) }

// Fatal for logging fatal errors
func Fatal(msg string, args ...any) {
	// Fatal errors should be logged to stderr even if the logger is disabled.
	New(NewHandler(os.Stderr, &Options{})).Log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}

// WriteLogger is a wrapper around Logger to implement io.Writer
type WriteLogger struct {
	logger *Logger
}

// NewWriteLogger creates a new WriteLogger
func NewWriteLogger(logger *Logger) *WriteLogger {
	return &WriteLogger{logger: logger}
}

func (l *WriteLogger) Write(p []byte) (n int, err error) {
	l.logger.Debug(strings.TrimSpace(string(p)))
	return len(p), nil
}

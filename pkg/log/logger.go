package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/samber/lo"
)

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
	LevelFatal = slog.Level(12)

	PrefixContainerImage   = "image"
	PrefixPackage          = "pkg"
	PrefixVulnerability    = "vuln"
	PrefixMisconfiguration = "misconfig"
	PrefixSecret           = "secret"
	PrefixLicense          = "license"
	PrefixVulnerabilityDB  = "vulndb"
	PrefixJavaDB           = "javadb"
	PrefixSPDX             = "spdx"
	PrefixCycloneDX        = "cyclonedx"
)

// Format represents the output format of the logger.
type Format string

const (
	// FormatText is the human-readable, colorized output.
	FormatText Format = "text"
	// FormatJSON is one JSON object per line, for machine consumption.
	FormatJSON Format = "json"
)

// Formats is the list of supported log formats.
var Formats = []Format{
	FormatText,
	FormatJSON,
}

// Logger is an alias of slog.Logger
type Logger = slog.Logger

// New creates a new Logger with the given non-nil Handler.
func New(h slog.Handler) *Logger {
	return slog.New(h)
}

type initConfig struct {
	format Format
}

// InitOption customizes the logger initialization.
type InitOption func(*initConfig)

// WithFormat sets the output format of the logger. It defaults to [FormatText].
func WithFormat(format Format) InitOption {
	return func(c *initConfig) {
		c.format = format
	}
}

// InitLogger initializes the logger variable and flushes the buffered logs if needed.
func InitLogger(debug, disable bool, opts ...InitOption) {
	conf := initConfig{format: FormatText}
	for _, opt := range opts {
		opt(&conf)
	}

	level := lo.Ternary(debug, slog.LevelDebug, slog.LevelInfo)
	out := lo.Ternary(disable, io.Discard, io.Writer(os.Stderr))

	var h slog.Handler
	if conf.format == FormatJSON {
		h = NewJSONHandler(out, &Options{Level: level})
	} else {
		h = NewHandler(out, &Options{Level: level})
	}

	// Flush the buffered logs if needed.
	if d, ok := slog.Default().Handler().(*DeferredHandler); ok {
		d.Flush(h)
	}

	slog.SetDefault(New(h))
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
	switch h := slog.Default().Handler().(type) {
	case *ColorHandler:
		h.out = os.Stderr
	case *JSONHandler:
		// The writer cannot be swapped in place, so the handler is rebuilt
		// to keep the output format the user asked for.
		slog.SetDefault(New(h.withWriter(os.Stderr)))
	default:
		slog.SetDefault(New(NewHandler(os.Stderr, &Options{})))
	}
	slog.Default().Log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}

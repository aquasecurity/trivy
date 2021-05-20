package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"

	flog "github.com/aquasecurity/fanal/log"
	dlog "github.com/aquasecurity/go-dep-parser/pkg/log"
)

var (
	// Logger is the global variable for logging
	Logger      *zap.SugaredLogger
	debugOption bool
)

func init() {
	// Set the default logger
	Logger, _ = NewLogger(false, false) // nolint: errcheck
}

// InitLogger initialize the logger variable
func InitLogger(debug, disable bool) (err error) {
	debugOption = debug
	Logger, err = NewLogger(debug, disable)
	if err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// Set logger for go-dep-parser
	dlog.SetLogger(Logger)

	// Set logger for fanal
	flog.SetLogger(Logger)

	return nil

}

// NewLogger is the factory method to return the instance of logger
func NewLogger(debug, disable bool) (*zap.SugaredLogger, error) {
	// First, define our level-handling logic.
	errorPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})
	logPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		if debug {
			return lvl < zapcore.ErrorLevel
		}
		// Not enable debug level
		return zapcore.DebugLevel < lvl && lvl < zapcore.ErrorLevel
	})

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "Time",
		LevelKey:       "Level",
		NameKey:        "Name",
		CallerKey:      "Caller",
		MessageKey:     "Msg",
		StacktraceKey:  "St",
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// High-priority output should also go to standard error, and low-priority
	// output should also go to standard out.
	consoleLogs := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)
	if disable {
		devNull, err := os.Create(os.DevNull)
		if err != nil {
			return nil, err
		}
		// Discard low-priority output
		consoleLogs = zapcore.Lock(devNull)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errorPriority),
		zapcore.NewCore(consoleEncoder, consoleLogs, logPriority),
	)

	opts := []zap.Option{zap.ErrorOutput(zapcore.Lock(os.Stderr))}
	if debug {
		opts = append(opts, zap.Development())
	}
	logger := zap.New(core, opts...)

	return logger.Sugar(), nil
}

// Fatal for logging fatal errors
func Fatal(err error) {
	if debugOption {
		Logger.Fatalf("%+v", err)
	}
	Logger.Fatal(err)
}

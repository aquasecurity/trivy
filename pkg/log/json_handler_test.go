package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

func TestJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	logger.Debug("debug message", "key1", "value1", "key2", 2)
	logger.Info("info message", "key3", true)
	logger.Warn("warn message", slog.Group("group1", slog.Int("key4", 42)))
	logger.Error("error message", log.Err(errors.New("something went wrong")))

	want := []map[string]any{
		{
			"level": "DEBUG",
			"msg":   "debug message",
			"key1":  "value1",
			"key2":  float64(2),
		},
		{
			"level": "INFO",
			"msg":   "info message",
			"key3":  true,
		},
		{
			"level":  "WARN",
			"msg":    "warn message",
			"group1": map[string]any{"key4": float64(42)},
		},
		{
			// Errors are not marshalable to JSON, so the message is logged instead.
			"level": "ERROR",
			"msg":   "error message",
			"err":   "something went wrong",
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

func TestJSONHandlerLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelWarn}))

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")

	// Only the message at or above the configured level is emitted.
	want := []map[string]any{
		{
			"level": "WARN",
			"msg":   "warn message",
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

func TestJSONHandlerFatalLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	// Trivy's custom level would otherwise be rendered as "ERROR+4".
	logger.Log(t.Context(), log.LevelFatal, "fatal message")

	want := []map[string]any{
		{
			"level": "FATAL",
			"msg":   "fatal message",
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

func TestJSONHandlerPrefix(t *testing.T) {
	tests := []struct {
		name string
		log  func(logger *log.Logger)
		want map[string]any
	}{
		{
			name: "attr prefix",
			log: func(logger *log.Logger) {
				logger.Info("info message", log.Prefix(log.PrefixVulnerability))
			},
			want: map[string]any{
				"level":  "INFO",
				"msg":    "info message",
				"prefix": "vuln",
			},
		},
		{
			name: "handler prefix",
			log: func(logger *log.Logger) {
				logger.With(log.Prefix(log.PrefixSecret)).Info("info message")
			},
			want: map[string]any{
				"level":  "INFO",
				"msg":    "info message",
				"prefix": "secret",
			},
		},
		{
			name: "contextual prefix",
			log: func(logger *log.Logger) {
				ctx := log.WithContextPrefix(context.Background(), log.PrefixJavaDB)
				logger.InfoContext(ctx, "info message")
			},
			want: map[string]any{
				"level":  "INFO",
				"msg":    "info message",
				"prefix": "javadb",
			},
		},
		{
			name: "no prefix",
			log: func(logger *log.Logger) {
				logger.Info("info message")
			},
			want: map[string]any{
				"level": "INFO",
				"msg":   "info message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

			tt.log(logger)

			// The prefix is a dedicated field rather than a decoration on the message.
			assert.Equal(t, []map[string]any{tt.want}, parseJSONLines(t, buf.String()))
		})
	}
}

func TestJSONHandlerContextAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	ctx := log.WithContextAttrs(context.Background(), log.String("key1", "value1"))
	logger.InfoContext(ctx, "info message", "key2", "value2")

	want := []map[string]any{
		{
			"level": "INFO",
			"msg":   "info message",
			"key1":  "value1",
			"key2":  "value2",
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

func TestJSONHandlerWithAttrsAndWithGroup(t *testing.T) {
	var buf bytes.Buffer
	baseLogger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	logger := baseLogger.
		With("key1", "value1").
		WithGroup("group1").
		With("key2", "value2")

	logger.Info("info message", "key3", true)

	want := []map[string]any{
		{
			"level": "INFO",
			"msg":   "info message",
			"key1":  "value1",
			"group1": map[string]any{
				"key2": "value2",
				"key3": true,
			},
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

func TestJSONSlogtest(t *testing.T) {
	var buf bytes.Buffer
	newHandler := func(*testing.T) slog.Handler {
		buf.Reset()
		return log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug})
	}

	results := func(t *testing.T) map[string]any {
		var m map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &m))
		return m
	}

	slogtest.Run(t, newHandler, results)
}

// parseJSONLines parses the emitted log lines and drops the timestamp, which is not deterministic.
func parseJSONLines(t *testing.T, s string) []map[string]any {
	t.Helper()

	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(s), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoErrorf(t, json.Unmarshal([]byte(line), &m), "invalid JSON log line: %s", line)
		delete(m, slog.TimeKey)
		lines = append(lines, m)
	}
	return lines
}

// stringerScanner mimics table.Scanner: an interface value with no exported
// fields that defines String for logging.
type stringerScanner struct{ name string }

func (s stringerScanner) String() string { return s.name }

func TestJSONHandlerStringer(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(log.NewJSONHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	logger.Info("scanner message",
		log.Any("scanner", stringerScanner{name: "secret"}),
		log.Any("scanners", []fmt.Stringer{
			stringerScanner{name: "secret"},
			stringerScanner{name: "license"},
		}),
	)

	// Without the conversion these marshal to {} and [{},{}].
	want := []map[string]any{
		{
			"level":    "INFO",
			"msg":      "scanner message",
			"scanner":  "secret",
			"scanners": []any{"secret", "license"},
		},
	}
	assert.Equal(t, want, parseJSONLines(t, buf.String()))
}

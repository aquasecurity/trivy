package log_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"testing/slogtest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/log"
)

func TestColorHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelDebug}))

	// Test logging with different levels, attributes, and groups.
	logger.Debug("debug message", "key1", "value1", "key2", 2)
	logger.Info("info message", "key3", true)
	logger.Warn("warn message", slog.Group("group1", slog.Int("key4", 42)))
	logger.Error("error message", slog.Group("group2", slog.String("key5", "value5")))

	got := buf.String()

	wantLines := []string{
		`DEBUG	debug message	key1="value1" key2=2`,
		`INFO	info message	key3=true`,
		`WARN	warn message	group1.key4=42`,
		`ERROR	error message	group2.key5="value5"`,
	}
	compareLines(t, got, wantLines)
}

func TestSlog(t *testing.T) {
	logger := slog.New(log.NewHandler(os.Stdout, &log.Options{Level: slog.LevelWarn}))
	logger.Info("foo")
	logger.Warn("warn message", slog.Group("group2", slog.String("key5", "value5")))
	logger.Error("error", slog.Int("key3", 3), slog.Group("group3", slog.String("key4", "value4")))
}

func TestWithAttrsAndWithGroup(t *testing.T) {
	t.Run("single group", func(t *testing.T) {
		var buf bytes.Buffer
		baseLogger := log.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelWarn}))

		// Test logging with WithContextAttrs and WithGroup.
		logger := baseLogger.
			With("key1", "value1").
			WithGroup("group1").
			With("key2", "value2")

		logger.Debug("debug message")
		logger.Info("info message", "key3", true)
		logger.Warn("warn message", log.Err(errors.New("error")))
		logger.Error("error message", slog.Group("group2", slog.Int("key4", 4)))

		got := buf.String()
		wantLines := []string{
			`WARN	warn message	key1="value1" group1.key2="value2" group1.err="error"`,
			`ERROR	error message	key1="value1" group1.key2="value2" group1.group2.key4=4`,
		}
		compareLines(t, got, wantLines)
	})

	t.Run("multiple groups", func(t *testing.T) {
		var buf bytes.Buffer
		baseLogger := log.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelWarn}))

		// Test logging with WithContextAttrs and WithGroup.
		logger := baseLogger.
			WithGroup("group1").
			With("key1", "value1").
			WithGroup("group2")

		logger.Error("error message", slog.Group("group3", slog.Int("key2", 2)))

		got := buf.String()
		wantLines := []string{
			`ERROR	error message	group1.key1="value1" group1.group2.group3.key2=2`,
		}
		compareLines(t, got, wantLines)
	})

	t.Run("prefix", func(t *testing.T) {
		var buf bytes.Buffer
		logger := log.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelWarn}))
		logger.Error("error message", log.Prefix("prefix1"), log.String("key1", "value1"))

		wantLines := []string{
			`ERROR	[prefix1] error message	key1="value1"`,
		}
		compareLines(t, buf.String(), wantLines)

		buf.Reset()
		log.SetDefault(logger)
		log.WithPrefix("prefix2").Error("error message", log.String("key1", "value1"))

		wantLines = []string{
			`ERROR	[prefix2] error message	key1="value1"`,
		}
		compareLines(t, buf.String(), wantLines)
	})
}

func TestContext(t *testing.T) {
	t.Run("with context prefix", func(t *testing.T) {
		var buf bytes.Buffer
		baseLogger := log.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelInfo}))

		// Test logging with WithContextPrefix
		ctx := context.Background()
		ctx = log.WithContextPrefix(ctx, "prefix1")

		logger := baseLogger.With("key1", "value1").WithGroup("group1")
		logger.InfoContext(ctx, "info message", "key2", true)

		got := buf.String()
		wantLines := []string{
			`INFO	[prefix1] info message	key1="value1" group1.key2=true`,
		}
		compareLines(t, got, wantLines)
	})

	t.Run("with context attrs", func(t *testing.T) {
		var buf bytes.Buffer
		baseLogger := log.New(log.NewHandler(&buf, &log.Options{Level: slog.LevelInfo}))

		// Test logging with WithContextAttrs
		ctx := context.Background()
		ctx = log.WithContextAttrs(ctx, log.String("key1", "value1"))

		logger := baseLogger.WithGroup("group1")
		logger.InfoContext(ctx, "info message", "key2", true)

		got := buf.String()
		wantLines := []string{
			`INFO	info message	group1.key1="value1" group1.key2=true`,
		}
		compareLines(t, got, wantLines)
	})
}

func compareLines(t *testing.T, got string, wantLines []string) {
	// Strip color codes from the output.
	got = stripColorCodes(got)

	// Split the output into lines.
	gotLines := strings.Split(got, "\n")

	assert.Len(t, gotLines, len(wantLines)+1) // Expecting log lines and an empty line.

	for i, wantLine := range wantLines {
		if i >= len(gotLines) {
			break
		}

		ss := strings.Split(gotLines[i], "\t")
		gotLevel, gotMessage, gotAttrs := ss[1], ss[2], ss[3]

		ss = strings.Split(wantLine, "\t")
		wantLevel, wantMessage, wantAttrs := ss[0], ss[1], ss[2]

		assert.Equal(t, wantLevel, gotLevel)
		assert.Equal(t, wantMessage, gotMessage)
		assert.Equal(t, wantAttrs, gotAttrs)
	}
	assert.Empty(t, strings.TrimSpace(gotLines[len(gotLines)-1])) // Last line should be empty.
}

func stripColorCodes(s string) string {
	// This is a simplified version that only handles the color codes used in ColorHandler.
	s = strings.ReplaceAll(s, "\x1b[90m", "") // FgHiBlack
	s = strings.ReplaceAll(s, "\x1b[94m", "") // FgHiBlue
	s = strings.ReplaceAll(s, "\x1b[93m", "") // FgHiYellow
	s = strings.ReplaceAll(s, "\x1b[91m", "") // FgHiRed
	s = strings.ReplaceAll(s, "\x1b[96m", "") // FgHiCyan
	s = strings.ReplaceAll(s, "\x1b[95m", "") // FgHiMagenta
	s = strings.ReplaceAll(s, "\x1b[97m", "") // FgWhite
	s = strings.ReplaceAll(s, "\x1b[0m", "")  // Reset
	return s
}

// TODO: slogtest.Run was added in Go 1.22. Waiting for https://github.com/aquasecurity/trivy/pull/6075.
func TestSlogtest(t *testing.T) {
	var buf bytes.Buffer
	newHandler := func(*testing.T) slog.Handler {
		buf.Reset()
		return log.NewHandler(&buf, &log.Options{Level: slog.LevelDebug})
	}

	results := func(*testing.T) map[string]any {
		for _, line := range strings.Split(buf.String(), "\n") {
			if line == "" {
				continue
			}
			m, err := parseLogLine(line)
			if err != nil {
				t.Fatalf("Failed to parse log line: %v", err)
			}
			return m
		}
		return nil
	}

	slogtest.Run(t, newHandler, results)
}

func parseLogLine(line string) (map[string]any, error) {
	parts := strings.SplitN(line, "\t", 4)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid log line format: %s", line)
	}

	m := make(map[string]any)
	if t, err := time.Parse(time.RFC3339, parts[0]); err == nil {
		m["time"] = t
		parts = parts[1:]
	}
	m["level"] = parts[0]
	m["msg"] = parts[1]

	if len(parts) == 3 {
		for _, attr := range strings.Split(parts[2], " ") {
			kv := strings.SplitN(attr, "=", 2)
			if len(kv) == 2 {
				parseAttr(m, kv[0], kv[1])
			}
		}
	}

	return m, nil
}

func parseAttr(attrs map[string]any, key, value string) {
	parts := strings.Split(key, ".")
	currentMap := attrs
	for i, part := range parts {
		if i == len(parts)-1 {
			currentMap[part] = strings.Trim(value, `"`)
		} else {
			if _, ok := currentMap[part]; !ok {
				currentMap[part] = make(map[string]any)
			}
			currentMap = currentMap[part].(map[string]any)
		}
	}
}

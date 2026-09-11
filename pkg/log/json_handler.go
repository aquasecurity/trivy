package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"

	"github.com/aquasecurity/trivy/pkg/clock"
)

// JSONHandler emits logs as JSON objects, one per line, for consumption by log
// aggregators such as Splunk or Loki.
//
// It wraps [slog.JSONHandler] rather than replacing it, and adds the parts of
// Trivy's logging model that the standard handler knows nothing about:
// contextual attributes and prefixes (see context.go), the custom
// [LevelFatal] level, and errors, which are not marshalable to JSON on their own.
type JSONHandler struct {
	opts   Options
	prefix string
	inner  slog.Handler
}

func NewJSONHandler(out io.Writer, opts *Options) *JSONHandler {
	h := &JSONHandler{}
	if opts != nil {
		h.opts = *opts
	}
	if h.opts.Level == nil {
		h.opts.Level = slog.LevelInfo
	}
	h.inner = slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level:       h.opts.Level,
		ReplaceAttr: replaceAttr,
	})
	return h
}

func (h *JSONHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *JSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := *h

	// Prefixes are rendered as a dedicated field, not as an ordinary attribute.
	rest := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if isLogPrefix(a) {
			h2.prefix = cleanPrefix(string(a.Value.Any().(logPrefix)))
			continue
		}
		rest = append(rest, a)
	}

	if len(rest) > 0 {
		h2.inner = h.inner.WithAttrs(rest)
	}
	return &h2
}

func (h *JSONHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := *h
	h2.inner = h.inner.WithGroup(name)
	return &h2
}

func (h *JSONHandler) Handle(ctx context.Context, r slog.Record) error {
	// For tests, use the fake clock's time.
	if c, ok := clock.Clock(ctx).(*clock.FakeClock); ok {
		r.Time = c.Now()
	}

	// The record is rebuilt so that the contextual attributes and the prefix,
	// which [slog.JSONHandler] does not know about, are included.
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if prefix := h.recordPrefix(ctx, r); prefix != "" {
		r2.AddAttrs(String(prefixKey, prefix))
	}
	r2.AddAttrs(contextualAttrs(ctx)...)
	r.Attrs(func(a slog.Attr) bool {
		// The prefix has already been added above.
		if !isLogPrefix(a) {
			r2.AddAttrs(a)
		}
		return true
	})

	return h.inner.Handle(ctx, r2)
}

// withWriter returns a copy of the handler that writes to out.
// It is used by [Fatal] to log to stderr even when the logger is disabled.
func (h *JSONHandler) withWriter(out io.Writer) *JSONHandler {
	h2 := NewJSONHandler(out, &h.opts)
	h2.prefix = h.prefix
	return h2
}

// recordPrefix returns the prefix from the record, the context or the handler, in that order.
func (h *JSONHandler) recordPrefix(ctx context.Context, r slog.Record) string {
	if p := string(findKey[logPrefix](prefixKey, r)); p != "" {
		return cleanPrefix(p)
	}
	if p := contextualPrefix(ctx); p != "" {
		return cleanPrefix(p)
	}
	return h.prefix
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	// Render the custom FATAL level by name instead of as "ERROR+4".
	if len(groups) == 0 && a.Key == slog.LevelKey {
		if level, ok := a.Value.Any().(slog.Level); ok {
			return slog.String(slog.LevelKey, levelString(level))
		}
		return a
	}

	a.Value = a.Value.Resolve()
	if isLogPrefix(a) {
		return slog.String(a.Key, cleanPrefix(string(a.Value.Any().(logPrefix))))
	}
	if a.Value.Kind() != slog.KindAny {
		return a
	}

	v := a.Value.Any()
	// Most error types marshal to "{}", so the message is logged instead.
	if err, ok := v.(error); ok {
		return slog.String(a.Key, err.Error())
	}
	// Interfaces and structs without exported fields also marshal to "{}".
	// Those that define String for logging, such as table.Scanner, are rendered
	// with it, mirroring what the text handler shows.
	if s, ok := v.(fmt.Stringer); ok {
		return slog.String(a.Key, s.String())
	}
	if ss, ok := stringSlice(v); ok {
		return slog.Any(a.Key, ss)
	}
	return a
}

var stringerType = reflect.TypeFor[fmt.Stringer]()

// stringSlice converts a slice of [fmt.Stringer], e.g. []table.Scanner, to a
// slice of strings so that it is logged as ["secret"] rather than [{}].
func stringSlice(v any) ([]string, bool) {
	rv := reflect.ValueOf(v)
	if k := rv.Kind(); k != reflect.Slice && k != reflect.Array {
		return nil, false
	}
	if !rv.Type().Elem().Implements(stringerType) {
		return nil, false
	}

	ss := make([]string, rv.Len())
	for i := range ss {
		ss[i] = rv.Index(i).Interface().(fmt.Stringer).String()
	}
	return ss, true
}

// cleanPrefix strips the decoration that [Prefix] and [WithContextPrefix] add
// for the text output, e.g. "[vuln] " becomes "vuln".
func cleanPrefix(prefix string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(prefix), "["), "]")
}

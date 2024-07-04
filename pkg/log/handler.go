package log

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
)

const (
	errKey    = "err"
	prefixKey = "prefix"
)

type ColorHandler struct {
	opts         Options
	prefix       string
	preformatted []byte   // data from WithGroup and WithAttrs
	groups       []string // groups from WithGroup
	mu           *sync.Mutex
	out          io.Writer
}

type Options struct {
	// Level reports the minimum level to log.
	// Levels with lower levels are discarded.
	// If nil, the Handler uses [slog.LevelInfo].
	Level slog.Leveler
}

func NewHandler(out io.Writer, opts *Options) *ColorHandler {
	h := &ColorHandler{
		out: out,
		mu:  &sync.Mutex{},
	}
	if opts != nil {
		h.opts = *opts
	}
	if h.opts.Level == nil {
		h.opts.Level = slog.LevelInfo
	}
	return h
}

func (h *ColorHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *ColorHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := *h
	// Add an unopened group to h2 without modifying h.
	h2.groups = make([]string, len(h.groups)+1)
	copy(h2.groups, h.groups)
	h2.groups[len(h2.groups)-1] = name
	return &h2
}

func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := *h

	// Force an append to copy the underlying array.
	h2.preformatted = slices.Clip(h.preformatted)

	// Pre-format the attributes.
	for _, a := range attrs {
		if isLogPrefix(a) {
			h2.prefix = string(a.Value.Any().(logPrefix))
			continue
		}
		h2.preformatted = h2.appendAttr(h2.preformatted, a, h.groups)
	}
	return &h2
}

func (h *ColorHandler) appendAttr(buf []byte, a slog.Attr, groups []string) []byte {
	// Resolve the Attr's value before doing anything else.
	a.Value = a.Value.Resolve()
	// Ignore empty Attrs and log prefixes.
	if a.Equal(slog.Attr{}) || isLogPrefix(a) {
		return buf
	}

	var key string
	for _, g := range groups {
		key += g + "."
	}
	key += a.Key

	switch a.Value.Kind() {
	case slog.KindString:
		// Quote string values, to make them easy to parse.
		buf = append(buf, key...)
		buf = append(buf, '=')
		buf = strconv.AppendQuote(buf, a.Value.String())
	case slog.KindTime:
		// Write times in a standard way, without the monotonic time.
		buf = append(buf, key...)
		buf = append(buf, '=')
		buf = a.Value.Time().AppendFormat(buf, time.RFC3339Nano)
	case slog.KindGroup:
		attrs := a.Value.Group()
		// Ignore empty groups.
		if len(attrs) == 0 {
			return buf
		}
		if a.Key != "" {
			groups = append(groups, a.Key)
		}
		for _, ga := range attrs {
			buf = h.appendAttr(buf, ga, groups)
		}
		buf = bytes.TrimRight(buf, " ") // Trim the trailing space.
	default:
		buf = append(buf, key...)
		buf = append(buf, '=')
		if err, ok := a.Value.Any().(error); ok {
			buf = append(buf, color.HiRedString(strconv.Quote(err.Error()))...)
		} else {
			buf = append(buf, a.Value.String()...)
		}
	}
	return append(buf, ' ')
}

func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	bufp := allocBuf()
	buf := *bufp
	defer func() {
		*bufp = buf
		freeBuf(bufp)
	}()

	// For tests, use the fake clock's time.
	if c, ok := clock.Clock(ctx).(*clock.FakeClock); ok {
		r.Time = c.Now()
	}

	buf = h.handle(ctx, buf, r)

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, err := h.out.Write(buf); err != nil {
		return xerrors.Errorf("failed to write log: %w", err)
	}

	return nil
}

func (h *ColorHandler) handle(ctx context.Context, buf []byte, r slog.Record) []byte {
	colorize := color.New()
	switch r.Level {
	case slog.LevelDebug:
		colorize = colorize.Add(color.FgHiBlack)
	case slog.LevelInfo:
		colorize = colorize.Add(color.FgHiBlue)
	case slog.LevelWarn:
		colorize = colorize.Add(color.FgHiYellow)
	case slog.LevelError:
		colorize = colorize.Add(color.FgHiRed)
	case LevelFatal:
		colorize = colorize.Add(color.FgRed)
	}

	// Timestamp
	if !r.Time.IsZero() {
		buf = append(buf, r.Time.Format(time.RFC3339)...)
		buf = append(buf, '\t')
	}

	// Level
	buf = append(buf, colorize.Sprint(levelString(r.Level))...)
	buf = append(buf, '\t')

	// Message
	buf = append(buf, h.Prefix(ctx, r)+r.Message...)
	if r.Level == LevelFatal {
		// Show the error and return early.
		format := lo.Ternary(h.opts.Level == slog.LevelDebug, "\n  - %+v\n", "\t%v\n")
		return fmt.Appendf(buf, format, h.Err(r))
	}

	// Attrs
	var preformatted []byte
	for _, a := range contextualAttrs(ctx) {
		preformatted = h.appendAttr(preformatted, a, h.groups)
	}
	preformatted = append(preformatted, h.preformatted...)

	if len(preformatted) > 0 || r.NumAttrs() > 0 {
		buf = append(buf, '\t')
	}

	if len(preformatted) > 0 {
		buf = append(buf, preformatted...)
	}
	r.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a, h.groups)
		return true
	})

	// Trim the trailing space.
	buf = bytes.TrimRight(buf, " ")
	buf = append(buf, '\n')

	return buf
}

// Err returns the error from the attrs, if any.
func (h *ColorHandler) Err(r slog.Record) error {
	return findKey[error](errKey, r)
}

// Prefix returns the prefix from the attrs, if any.
func (h *ColorHandler) Prefix(ctx context.Context, r slog.Record) string {
	if attrPrefix := string(findKey[logPrefix](prefixKey, r)); attrPrefix != "" {
		return attrPrefix
	}
	if ctxPrefix := contextualPrefix(ctx); ctxPrefix != "" {
		return ctxPrefix
	}
	return h.prefix
}

func findKey[T any](key string, r slog.Record) T {
	var v T
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != key {
			return true
		}

		var ok bool
		if v, ok = a.Value.Any().(T); !ok {
			return true
		}
		return false
	})
	return v
}

var (
	String   = slog.String
	Int64    = slog.Int64
	Int      = slog.Int
	Bool     = slog.Bool
	Time     = slog.Time
	Duration = slog.Duration
	Group    = slog.Group
	Any      = slog.Any
)

// Err returns an Attr that represents an error.
func Err(err error) slog.Attr {
	return slog.Any(errKey, err)
}

type logPrefix string

// Prefix returns an Attr that represents a prefix.
func Prefix(prefix string) slog.Attr {
	return slog.Any(prefixKey, logPrefix("["+prefix+"] "))
}

// FilePath returns an Attr that represents a filePath.
func FilePath(filePath string) slog.Attr {
	return String("file_path", filePath)
}

func isLogPrefix(a slog.Attr) bool {
	_, ok := a.Value.Any().(logPrefix)
	return ok
}

func levelString(level slog.Level) string {
	if level == LevelFatal {
		return "FATAL"
	}
	return level.String()
}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1024)
		return &b
	},
}

func allocBuf() *[]byte {
	return bufPool.Get().(*[]byte)
}

func freeBuf(b *[]byte) {
	// To reduce peak allocation, return only smaller buffers to the pool.
	const maxBufferSize = 16 << 10
	if cap(*b) <= maxBufferSize {
		*b = (*b)[:0]
		bufPool.Put(b)
	}
}

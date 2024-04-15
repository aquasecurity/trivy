package log

import (
	"context"
	"log/slog"
)

// prefixContextKey is the context key for logger.
// It is unexported to prevent collisions with context keys defined in other packages.
type prefixContextKey struct{}

// WithContextPrefix returns a new context with the given prefix.
func WithContextPrefix(ctx context.Context, prefix string) context.Context {
	if prefix == "" {
		return ctx
	}
	return context.WithValue(ctx, prefixContextKey{}, "["+prefix+"] ")
}

func contextualPrefix(ctx context.Context) string {
	if prefix, ok := ctx.Value(prefixContextKey{}).(string); ok {
		return prefix
	}
	return ""
}

// attrContextKey is the context key for logger.
// It is unexported to prevent collisions with context keys defined in other packages.
type attrContextKey struct{}

// WithContextAttrs returns a new context with the given attrs.
func WithContextAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	if len(attrs) == 0 {
		return ctx
	}
	if ctxAttrs := contextualAttrs(ctx); ctxAttrs != nil {
		attrs = append(ctxAttrs, attrs...)
	}
	return context.WithValue(ctx, attrContextKey{}, attrs)
}

func contextualAttrs(ctx context.Context) []slog.Attr {
	if attrs, ok := ctx.Value(attrContextKey{}).([]slog.Attr); ok {
		return attrs
	}
	return nil
}

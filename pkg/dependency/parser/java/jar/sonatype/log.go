package sonatype

import (
	"context"
	"log/slog"

	"github.com/aquasecurity/trivy/pkg/log"
)

// logger implements LeveledLogger
// https://github.com/hashicorp/go-retryablehttp/blob/991b9d0a42d13014e3689dd49a94c02be01f4237/client.go#L285-L290
type handler struct {
	slog.Handler
}

func newLogger() *log.Logger {
	return log.New(&handler{slog.Default().Handler()}).With(log.Prefix("sonatype"))
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	switch r.Message {
	case "request failed":
		// Use Debug to suppress errors on failure
		r.Level = log.LevelDebug
	case "performing request":
		// This message is displayed too much
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

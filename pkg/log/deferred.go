package log

import (
	"context"
	"log/slog"
	"slices"
)

func init() {
	// Set the default logger so that logs are buffered until the logger is initialized.
	slog.SetDefault(New(&DeferredHandler{records: new([]deferredRecord)}))
}

// DeferredHandler is needed to save logs and print them after calling `PrintLogs()` command.
// For example, this may be necessary when the logger is not yet initialized, but messages need to be transmitted.
// In this case, the messages are saved and printed when the logger is initialized.
type DeferredHandler struct {
	attrs []slog.Attr

	// Shared with all instances of the handler.
	// NOTE: non-thread safe
	records *[]deferredRecord
}

type deferredRecord struct {
	ctx context.Context
	slog.Record
}

func (*DeferredHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (d *DeferredHandler) Handle(ctx context.Context, record slog.Record) error {
	record.AddAttrs(d.attrs...)
	*d.records = append(*d.records, deferredRecord{
		ctx:    ctx,
		Record: record,
	})
	return nil
}

func (d *DeferredHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h := *d
	h.attrs = slices.Clip(d.attrs)
	h.attrs = append(h.attrs, attrs...)
	return &h
}

func (*DeferredHandler) WithGroup(_ string) slog.Handler {
	panic("WithGroup is not implemented")
}

func (d *DeferredHandler) Flush(h slog.Handler) {
	for _, record := range *d.records {
		if !h.Enabled(record.ctx, record.Level) {
			continue
		}
		_ = h.Handle(record.ctx, record.Record)
	}
	d.records = nil
}

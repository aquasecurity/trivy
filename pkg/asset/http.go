package asset

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
)

type HTTP struct {
	url  string
	opts Options
}

func NewHTTP(location string, assetOpts Options) *HTTP {
	return &HTTP{
		url:  location,
		opts: assetOpts,
	}
}

func (h *HTTP) Location() string {
	return h.url
}

func (h *HTTP) Download(ctx context.Context, dir string) error {
	_, err := downloader.Download(ctx, h.url, dir, ".", downloader.Options{
		Insecure: h.opts.Insecure,
	})
	if err != nil {
		return xerrors.Errorf("failed to download artifact via HTTP: %w", err)
	}
	return nil
}

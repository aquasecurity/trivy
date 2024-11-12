package asset

import (
	"context"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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

func (h *HTTP) ShouldTryOtherRepo(err error) bool {
	// go-getter uses `bad response code: %d` format for error.
	// cf. https://github.com/hashicorp/go-getter/blob/6077ad5a32c0f4834467b552e1542f9920c6be6c/get_http.go#L275-L277
	// we need to parse error to get status code.
	e := err.Error()
	i := strings.LastIndex(e, "bad response code: ")
	if i == -1 {
		return false
	}

	e = e[i+19:] // e.g. "bad response code: 500" => "500"
	statusCode, convertErr := strconv.Atoi(e)
	if convertErr != nil {
		return false
	}

	// Create transport.Error with detected status code to check this error using `Temporary()` function.
	terr := &transport.Error{
		StatusCode: statusCode,
	}

	return shouldTryOtherRepo(terr)
}

package asset

import (
	"context"
	"strings"

	"github.com/aquasecurity/trivy/pkg/version/doc"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Options struct {
	// For OCI
	MediaType string // Accept any media type if not specified

	// Common
	Filename string // Use the annotation if not specified
	Quiet    bool

	types.RegistryOptions
}

type Assets []Asset

type Asset interface {
	Location() string
	Download(ctx context.Context, dst string) error
	ShouldTryOtherRepo(err error) bool
}

func NewAssets(locations []string, assetOpts Options, opts ...Option) Assets {
	var assets Assets
	for _, location := range locations {
		switch {
		case strings.HasPrefix(location, "https://"), strings.HasPrefix(location, "http://"):
			assets = append(assets, NewHTTP(location, assetOpts))
		default:
			assets = append(assets, NewOCI(location, assetOpts, opts...))
		}
	}
	return assets
}

// Download downloads artifacts until one of them succeeds.
// Attempts to download next artifact if the first one fails due to a temporary error.
func (a Assets) Download(ctx context.Context, dst string) error {
	var errs error
	for i, art := range a {
		logger := log.With("location", art.Location())
		logger.InfoContext(ctx, "Downloading artifact...")
		err := art.Download(ctx, dst)
		if err == nil {
			logger.InfoContext(ctx, "OCI successfully downloaded")
			return nil
		}

		if !art.ShouldTryOtherRepo(err) {
			return xerrors.Errorf("failed to download artifact from %s: %w", art.Location(), err)
		}
		logger.ErrorContext(ctx, "Failed to download artifact", log.Err(err))
		if i < len(a)-1 {
			log.InfoContext(ctx, "Trying to download artifact from other location...") // Use the default logger
		}
		errs = multierror.Append(errs, err)
	}

	return xerrors.Errorf("failed to download artifact from any source: %w", errs)
}

func shouldTryOtherRepo(terr *transport.Error) bool {
	for _, diagnostic := range terr.Errors {
		// For better user experience
		if diagnostic.Code == transport.DeniedErrorCode || diagnostic.Code == transport.UnauthorizedErrorCode {
			// e.g. https://aquasecurity.github.io/trivy/latest/docs/references/troubleshooting/#db
			log.Warnf("See %s", doc.URL("/docs/references/troubleshooting/", "db"))
			break
		}
	}

	// try the following artifact only if a temporary error occurs
	return terr.Temporary()
}

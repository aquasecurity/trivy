package artifact

import (
	"context"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"net/http"
)

func initializeClientScanner(ctx context.Context, target string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	remoteAddr string, customHeaders http.Header,
	insecure bool, artifactOpt artifact.Option, configScannerOptions config.ScannerOption) (scanner.Scanner, func(), error) {

	if target != "" {
		// Scan tar file
		s, err := initializeRemoteArchiveScanner(ctx, target, ac, client.CustomHeaders(customHeaders),
			client.RemoteURL(remoteAddr), client.Insecure(insecure), artifactOpt, configScannerOptions)
		if err != nil {
			return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
		return s, func() {}, nil
	}

	// Scan an image in Docker Engine or Docker Registry
	dockerOpt, err := types.GetDockerOption(insecure)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}

	s, cleanup, err := initializeRemoteDockerScanner(ctx, target, ac, client.CustomHeaders(customHeaders),
		client.RemoteURL(remoteAddr), client.Insecure(insecure), dockerOpt, artifactOpt, configScannerOptions)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}

	return s, cleanup, nil
}

func ClientRun(cliCtx *cli.Context) error {
	opt, err := NewOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}
	ctx, cancel := context.WithTimeout(cliCtx.Context, opt.Timeout)
	defer cancel()

	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	err = runWithTimeout(ctx, opt, initializeClientScanner, initRemoteCache)
	if xerrors.Is(err, context.DeadlineExceeded) {
		log.Logger.Warn("Increase --timeout value")
	}
	return err
}

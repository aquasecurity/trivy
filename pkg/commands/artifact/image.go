package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

// imageStandaloneScanner initializes a container image scanner in standalone mode
// $ trivy image alpine:3.15
func imageStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	dockerOpt, err := types.GetDockerOption(conf.ArtifactOption.InsecureSkipTLS)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	s, cleanup, err := initializeDockerScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache,
		dockerOpt, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveStandaloneScanner initializes an image archive scanner in standalone mode
// $ trivy image --input alpine.tar
func archiveStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

// imageRemoteScanner initializes a container image scanner in client/server mode
// $ trivy image --server localhost:4954 alpine:3.15
func imageRemoteScanner(ctx context.Context, conf ScannerConfig) (
	scanner.Scanner, func(), error) {
	// Scan an image in Docker Engine, Docker Registry, etc.
	dockerOpt, err := types.GetDockerOption(conf.ArtifactOption.InsecureSkipTLS)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}

	s, cleanup, err := initializeRemoteDockerScanner(ctx, conf.Target, conf.ArtifactCache, conf.RemoteOption,
		dockerOpt, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// archiveRemoteScanner initializes an image archive scanner in client/server mode
// $ trivy image --server localhost:4954 --input alpine.tar
func archiveRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	// Scan tar file
	s, err := initializeRemoteArchiveScanner(ctx, conf.Target, conf.ArtifactCache, conf.RemoteOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

// ImageRun runs scan on container image
func ImageRun(ctx *cli.Context) error {
	return Run(ctx, containerImageArtifact)
}

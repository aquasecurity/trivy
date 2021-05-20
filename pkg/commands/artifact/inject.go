// +build wireinject

package artifact

import (
	"context"
	"time"

	"github.com/google/wire"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, timeout time.Duration, disableAnalyzers []analyzer.Type,
	configScannerOption config.ScannerOption) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneDockerSet)
	return scanner.Scanner{}, nil, nil
}

func initializeArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, timeout time.Duration, disableAnalyzers []analyzer.Type,
	configScannerOption config.ScannerOption) (scanner.Scanner, error) {
	wire.Build(scanner.StandaloneArchiveSet)
	return scanner.Scanner{}, nil
}

func initializeFilesystemScanner(ctx context.Context, dir string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, disableAnalyzers []analyzer.Type, configScannerOption config.ScannerOption) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneFilesystemSet)
	return scanner.Scanner{}, nil, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache,
	localArtifactCache cache.LocalArtifactCache, disableAnalyzers []analyzer.Type, configScannerOption config.ScannerOption) (
	scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneRepositorySet)
	return scanner.Scanner{}, nil, nil
}

func initializeResultClient() result.Client {
	wire.Build(result.SuperSet)
	return result.Client{}
}

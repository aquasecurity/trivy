// +build wireinject

package artifact

import (
	"context"
	"time"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache,
	timeout time.Duration) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneDockerSet)
	return scanner.Scanner{}, nil, nil
}

func initializeArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache,
	timeout time.Duration) (scanner.Scanner, error) {
	wire.Build(scanner.StandaloneArchiveSet)
	return scanner.Scanner{}, nil
}

func initializeFilesystemScanner(ctx context.Context, dir string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneFilesystemSet)
	return scanner.Scanner{}, nil, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache) (scanner.Scanner, func(), error) {
	wire.Build(scanner.StandaloneRepositorySet)
	return scanner.Scanner{}, nil, nil
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

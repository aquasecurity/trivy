// +build wireinject

package client

import (
	"context"
	"time"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeDockerScanner(ctx context.Context, imageName string, layerCache cache.ImageCache, customHeaders client.CustomHeaders,
	url client.RemoteURL, timeout time.Duration) (scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteDockerSet)
	return scanner.Scanner{}, nil, nil
}

func initializeArchiveScanner(ctx context.Context, filePath string, layerCache cache.ImageCache, customHeaders client.CustomHeaders,
	url client.RemoteURL, timeout time.Duration) (scanner.Scanner, error) {
	wire.Build(scanner.RemoteArchiveSet)
	return scanner.Scanner{}, nil
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

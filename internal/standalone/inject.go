// +build wireinject

package standalone

import (
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeCacheClient(cacheDir string) (operation.Cache, error) {
	wire.Build(operation.SuperSet)
	return operation.Cache{}, nil
}

func initializeScanner(c cache.Cache) scanner.Scanner {
	wire.Build(scanner.StandaloneSet)
	return scanner.Scanner{}
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

// +build wireinject

package client

import (
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/client/library"
	"github.com/aquasecurity/trivy/pkg/rpc/client/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeScanner(cacheClient cache.Cache, ospkgCustomHeaders ospkg.CustomHeaders, libraryCustomHeaders library.CustomHeaders,
	ospkgURL ospkg.RemoteURL, libURL library.RemoteURL) scanner.Scanner {
	wire.Build(scanner.ClientSet)
	return scanner.Scanner{}
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

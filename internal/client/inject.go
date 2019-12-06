// +build wireinject

package client

import (
	"github.com/aquasecurity/trivy/internal/rpc/client/library"
	"github.com/aquasecurity/trivy/internal/rpc/client/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeScanner(ospkgToken ospkg.Token, libToken library.Token, ospkgURL ospkg.RemoteURL, libURL library.RemoteURL) scanner.Scanner {
	wire.Build(scanner.ClientSet)
	return scanner.Scanner{}
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

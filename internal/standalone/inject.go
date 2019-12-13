// +build wireinject

package standalone

import (
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/wire"
)

func initializeScanner() scanner.Scanner {
	wire.Build(scanner.StandaloneSet)
	return scanner.Scanner{}
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}

package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func Adapt(modules terraform.Modules) apigateway.APIGateway {
	return apigateway.APIGateway{
		APIs:        adaptAPIs(modules),
		DomainNames: adaptDomainNames(modules),
	}
}

func adaptAPIs(modules terraform.Modules) []apigateway.API {
	return append(adaptAPIsV1(modules), adaptAPIsV2(modules)...)
}

func adaptDomainNames(modules terraform.Modules) []apigateway.DomainName {
	return append(adaptDomainNamesV1(modules), adaptDomainNamesV2(modules)...)
}

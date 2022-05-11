package apigateway

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptDomainNamesV2(modules terraform.Modules) []apigateway.DomainName {

	var domainNames []apigateway.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_apigatewayv2_domain_name") {
			domainName := apigateway.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
				Version:        types.Int(2, nameBlock.GetMetadata()),
				SecurityPolicy: types.StringDefault("TLS_1_0", nameBlock.GetMetadata()),
			}
			if config := nameBlock.GetBlock("domain_name_configuration"); config.IsNotNil() {
				domainName.SecurityPolicy = config.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", config)
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}

package apigateway

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func adaptDomainNamesV2(modules terraform.Modules) []apigateway.DomainName {

	var domainNames []apigateway.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_apigatewayv2_domain_name") {
			var domainName apigateway.DomainName
			domainName.Metadata = nameBlock.GetMetadata()
			domainName.Version = types.Int(2, nameBlock.GetMetadata())
			domainName.Name = nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock)
			if config := nameBlock.GetBlock("domain_name_configuration"); config.IsNotNil() {
				domainName.SecurityPolicy = config.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", config)
			} else {
				domainName.SecurityPolicy = types.StringDefault("TLS_1_0", nameBlock.GetMetadata())
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}

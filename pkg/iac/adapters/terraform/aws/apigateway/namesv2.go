package apigateway

import (
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptDomainNamesV2(modules terraform.Modules) []v2.DomainName {

	var domainNames []v2.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_apigatewayv2_domain_name") {
			domainName := v2.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
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

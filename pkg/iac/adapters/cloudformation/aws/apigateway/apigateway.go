package apigateway

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway"
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an APIGateway instance
func Adapt(cfFile parser.FileContext) apigateway.APIGateway {
	return apigateway.APIGateway{
		V1: v1.APIGateway{
			APIs:        nil,
			DomainNames: nil,
		},
		V2: v2.APIGateway{
			APIs: getApis(cfFile),
		},
	}
}

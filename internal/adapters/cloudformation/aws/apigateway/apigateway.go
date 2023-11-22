package apigateway

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"
	v2 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v2"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
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

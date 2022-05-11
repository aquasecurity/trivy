package apigateway

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (gateway apigateway.APIGateway) {
	gateway.APIs = getApis(cfFile)
	return gateway
}

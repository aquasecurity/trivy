package lambda

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a lambda instance
func Adapt(cfFile parser.FileContext) lambda.Lambda {
	return lambda.Lambda{
		Functions: getFunctions(cfFile),
	}
}

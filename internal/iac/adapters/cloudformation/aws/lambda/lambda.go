package lambda

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
)

// Adapt adapts a lambda instance
func Adapt(cfFile parser.FileContext) lambda.Lambda {
	return lambda.Lambda{
		Functions: getFunctions(cfFile),
	}
}

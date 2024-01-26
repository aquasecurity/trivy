package lambda

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a lambda instance
func Adapt(cfFile parser.FileContext) lambda.Lambda {
	return lambda.Lambda{
		Functions: getFunctions(cfFile),
	}
}

package lambda

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result lambda.Lambda) {

	result.Functions = getFunctions(cfFile)
	return result

}

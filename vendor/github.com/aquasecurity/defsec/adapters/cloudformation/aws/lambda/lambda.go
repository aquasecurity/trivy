package lambda

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/lambda"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result lambda.Lambda) {

	result.Functions = getFunctions(cfFile)
	return result

}

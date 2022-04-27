package cloudwatch

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/cloudwatch"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudwatch.CloudWatch) {

	result.LogGroups = getLogGroups(cfFile)
	return result

}

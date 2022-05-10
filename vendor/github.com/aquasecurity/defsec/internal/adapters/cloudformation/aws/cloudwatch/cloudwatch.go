package cloudwatch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result cloudwatch.CloudWatch) {

	result.LogGroups = getLogGroups(cfFile)
	return result

}

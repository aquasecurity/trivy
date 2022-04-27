package autoscaling

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/autoscaling"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result autoscaling.Autoscaling) {
	result.LaunchConfigurations = getLaunchConfigurations(cfFile)
	result.LaunchTemplates = getLaunchTemplates(cfFile)
	return result
}

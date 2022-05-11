package autoscaling

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result autoscaling.Autoscaling) {
	result.LaunchConfigurations = getLaunchConfigurations(cfFile)
	result.LaunchTemplates = getLaunchTemplates(cfFile)
	return result
}

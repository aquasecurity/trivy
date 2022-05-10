package ebs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ebs"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ebs.EBS) {

	result.Volumes = getVolumes(cfFile)
	return result

}

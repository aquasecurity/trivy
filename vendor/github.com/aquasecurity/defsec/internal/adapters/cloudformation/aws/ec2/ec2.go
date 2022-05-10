package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ec2.EC2) {

	result.Instances = getInstances(cfFile)
	return result
}

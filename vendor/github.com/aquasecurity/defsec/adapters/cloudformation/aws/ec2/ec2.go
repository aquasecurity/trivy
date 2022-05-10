package ec2

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ec2.EC2) {

	result.Instances = getInstances(cfFile)
	return result
}

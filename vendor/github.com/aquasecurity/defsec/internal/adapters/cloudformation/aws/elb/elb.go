package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result elb.ELB) {

	result.LoadBalancers = getLoadBalancers(cfFile)
	return result
}

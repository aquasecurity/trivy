package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an ELB instance
func Adapt(cfFile parser.FileContext) elb.ELB {
	return elb.ELB{
		LoadBalancers: getLoadBalancers(cfFile),
	}
}

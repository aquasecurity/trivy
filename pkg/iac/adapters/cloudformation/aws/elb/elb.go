package elb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an ELB instance
func Adapt(cfFile parser.FileContext) elb.ELB {
	return elb.ELB{
		LoadBalancers: getLoadBalancers(cfFile),
	}
}

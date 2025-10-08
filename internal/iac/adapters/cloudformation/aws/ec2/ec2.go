package ec2

import (
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
)

// Adapt adapts an EC2 instance
func Adapt(cfFile parser.FileContext) ec2.EC2 {
	return ec2.EC2{
		LaunchConfigurations: getLaunchConfigurations(cfFile),
		LaunchTemplates:      getLaunchTemplates(cfFile),
		Instances:            getInstances(cfFile),
		VPCs:                 getVPCs(cfFile),
		NetworkACLs:          getNetworkACLs(cfFile),
		SecurityGroups:       getSecurityGroups(cfFile),
		Subnets:              getSubnets(cfFile),
		Volumes:              getVolumes(cfFile),
	}
}

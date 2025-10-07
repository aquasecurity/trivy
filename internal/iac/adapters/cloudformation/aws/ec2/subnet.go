package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func getSubnets(ctx parser.FileContext) (subnets []ec2.Subnet) {

	subnetResources := ctx.GetResourcesByType("AWS::EC2::Subnet")
	for _, r := range subnetResources {

		subnet := ec2.Subnet{
			Metadata:            r.Metadata(),
			MapPublicIpOnLaunch: r.GetBoolProperty("MapPublicIpOnLaunch"),
		}

		subnets = append(subnets, subnet)
	}
	return subnets
}

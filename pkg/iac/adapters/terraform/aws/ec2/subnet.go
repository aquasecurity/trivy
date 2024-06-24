package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptSubnets(modules terraform.Modules) []ec2.Subnet {
	var subnets []ec2.Subnet
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_subnet") {
			subnets = append(subnets, adaptSubnet(resource, module))
		}
	}
	return subnets
}

func adaptSubnet(resource *terraform.Block, module *terraform.Module) ec2.Subnet {
	mapPublicIpOnLaunchAttr := resource.GetAttribute("map_public_ip_on_launch")
	mapPublicIpOnLaunchVal := mapPublicIpOnLaunchAttr.AsBoolValueOrDefault(false, resource)

	return ec2.Subnet{
		Metadata:            resource.GetMetadata(),
		MapPublicIpOnLaunch: mapPublicIpOnLaunchVal,
	}
}

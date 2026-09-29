package computing

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptInstances(modules terraform.Modules) []computing.Instance {
	var instances []computing.Instance

	for _, resource := range modules.GetResourcesByType("nifcloud_instance") {
		instances = append(instances, adaptInstance(resource))
	}
	return instances
}

func adaptInstance(resource *terraform.Block) computing.Instance {
	var networkInterfaces []computing.NetworkInterface
	networkInterfaceBlocks := resource.GetBlocks("network_interface")
	for _, networkInterfaceBlock := range networkInterfaceBlocks {
		networkInterfaces = append(
			networkInterfaces,
			computing.NetworkInterface{
				Metadata:  networkInterfaceBlock.GetMetadata(),
				NetworkID: networkInterfaceBlock.GetAttribute("network_id").AsStringValueOrDefault("", resource),
			},
		)
	}

	return computing.Instance{
		Metadata:          resource.GetMetadata(),
		SecurityGroup:     resource.GetAttribute("security_group").AsStringValueOrDefault("", resource),
		NetworkInterfaces: networkInterfaces,
	}
}

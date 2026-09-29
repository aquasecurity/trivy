package nas

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/nas"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptNASInstances(modules terraform.Modules) []nas.NASInstance {
	var nasInstances []nas.NASInstance

	for _, resource := range modules.GetResourcesByType("nifcloud_nas_instance") {
		nasInstances = append(nasInstances, adaptNASInstance(resource))
	}
	return nasInstances
}

func adaptNASInstance(resource *terraform.Block) nas.NASInstance {
	return nas.NASInstance{
		Metadata:  resource.GetMetadata(),
		NetworkID: resource.GetAttribute("network_id").AsStringValueOrDefault("net-COMMON_PRIVATE", resource),
	}
}

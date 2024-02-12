package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) compute.Compute {
	return compute.Compute{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform.Modules) []compute.Instance {
	var instances []compute.Instance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("cloudstack_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *terraform.Block) compute.Instance {
	userDataAttr := resource.GetAttribute("user_data")
	var encoded []byte
	var err error

	if userDataAttr.IsNotNil() && userDataAttr.IsString() {
		encoded, err = base64.StdEncoding.DecodeString(userDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(userDataAttr.Value().AsString())
		}
		return compute.Instance{
			Metadata: resource.GetMetadata(),
			UserData: types.String(string(encoded), userDataAttr.GetMetadata()),
		}
	}

	return compute.Instance{
		Metadata: resource.GetMetadata(),
		UserData: types.StringDefault("", resource.GetMetadata()),
	}
}

package cloudstack

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}

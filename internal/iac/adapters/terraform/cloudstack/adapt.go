package cloudstack

import (
	"github.com/aquasecurity/trivy/internal/iac/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/trivy/internal/iac/providers/cloudstack"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}

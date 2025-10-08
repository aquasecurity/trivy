package cloudstack

import (
	"github.com/aquasecurity/trivy/internal/iac/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}

package cloudstack

import (
	"github.com/aquasecurity/trivy/internal/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/trivy/pkg/providers/cloudstack"
	"github.com/aquasecurity/trivy/pkg/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}

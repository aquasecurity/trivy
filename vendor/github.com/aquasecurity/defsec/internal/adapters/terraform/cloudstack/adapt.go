package cloudstack

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/defsec/pkg/providers/cloudstack"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}

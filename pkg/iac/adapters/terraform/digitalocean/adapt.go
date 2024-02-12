package digitalocean

import (
	"github.com/aquasecurity/defsec/pkg/providers/digitalocean"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/digitalocean/spaces"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

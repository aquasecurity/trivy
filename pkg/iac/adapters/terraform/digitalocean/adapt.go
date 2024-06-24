package digitalocean

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/digitalocean/spaces"
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

package digitalocean

import (
	"github.com/aquasecurity/trivy/internal/iac/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/trivy/internal/iac/adapters/terraform/digitalocean/spaces"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

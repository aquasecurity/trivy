package digitalocean

import (
	"github.com/aquasecurity/trivy/internal/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/digitalocean/spaces"
	"github.com/aquasecurity/trivy/pkg/providers/digitalocean"
	"github.com/aquasecurity/trivy/pkg/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

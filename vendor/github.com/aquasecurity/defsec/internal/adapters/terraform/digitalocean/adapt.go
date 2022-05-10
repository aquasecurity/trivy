package digitalocean

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/digitalocean/spaces"
	"github.com/aquasecurity/defsec/pkg/providers/digitalocean"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

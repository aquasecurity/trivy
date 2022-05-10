package digitalocean

import (
	"github.com/aquasecurity/defsec/adapters/terraform/digitalocean/compute"
	"github.com/aquasecurity/defsec/adapters/terraform/digitalocean/spaces"
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/digitalocean"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}

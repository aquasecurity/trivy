package digitalocean

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy/internal/iac/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}

package digitalocean

import (
	"github.com/aquasecurity/trivy/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}

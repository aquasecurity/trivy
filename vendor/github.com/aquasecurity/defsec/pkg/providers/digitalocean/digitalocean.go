package digitalocean

import (
	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}

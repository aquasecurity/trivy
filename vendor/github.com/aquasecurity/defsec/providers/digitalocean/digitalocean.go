package digitalocean

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	types.Metadata
	Compute compute.Compute
	Spaces  spaces.Spaces
}

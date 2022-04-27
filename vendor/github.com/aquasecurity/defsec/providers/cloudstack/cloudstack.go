package cloudstack

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/cloudstack/compute"
)

type CloudStack struct {
	types.Metadata
	Compute compute.Compute
}

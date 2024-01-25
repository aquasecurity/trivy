package compute

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

type Network struct {
	Metadata    types.MisconfigMetadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}

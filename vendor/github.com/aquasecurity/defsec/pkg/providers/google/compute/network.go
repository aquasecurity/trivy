package compute

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}

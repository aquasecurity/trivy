package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}

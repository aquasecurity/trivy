package oracle

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	Metadata defsecTypes.MisconfigMetadata
	Pool     defsecTypes.StringValue // e.g. public-pool
}

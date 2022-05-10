package oracle

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	types.Metadata
	Pool types.StringValue // e.g. public-pool
}

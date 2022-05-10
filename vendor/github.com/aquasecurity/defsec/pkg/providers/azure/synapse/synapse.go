package synapse

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	types.Metadata
	EnableManagedVirtualNetwork types.BoolValue
}

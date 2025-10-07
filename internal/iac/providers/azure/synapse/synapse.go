package synapse

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	Metadata                    iacTypes.Metadata
	EnableManagedVirtualNetwork iacTypes.BoolValue
}

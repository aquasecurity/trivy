package synapse

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	Metadata                    defsecTypes.Metadata
	EnableManagedVirtualNetwork defsecTypes.BoolValue
}

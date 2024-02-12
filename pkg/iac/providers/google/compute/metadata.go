package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ProjectMetadata struct {
	Metadata      defsecTypes.Metadata
	EnableOSLogin defsecTypes.BoolValue
}

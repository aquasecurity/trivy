package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ProjectMetadata struct {
	Metadata      defsecTypes.MisconfigMetadata
	EnableOSLogin defsecTypes.BoolValue
}

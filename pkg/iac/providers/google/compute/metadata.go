package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}

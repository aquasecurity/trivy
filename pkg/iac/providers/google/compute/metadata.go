package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type MetadataFlags struct {
	EnableOSLogin       iacTypes.BoolValue
	BlockProjectSSHKeys iacTypes.BoolValue
	EnableSerialPort    iacTypes.BoolValue
}

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}

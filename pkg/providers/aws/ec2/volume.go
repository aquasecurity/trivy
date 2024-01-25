package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Volume struct {
	Metadata   defsecTypes.MisconfigMetadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

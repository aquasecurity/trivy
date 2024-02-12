package ec2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Volume struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

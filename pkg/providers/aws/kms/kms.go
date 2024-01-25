package kms

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	Metadata        defsecTypes.MisconfigMetadata
	Usage           defsecTypes.StringValue
	RotationEnabled defsecTypes.BoolValue
}

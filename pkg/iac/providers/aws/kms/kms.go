package kms

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	Metadata        defsecTypes.Metadata
	Usage           defsecTypes.StringValue
	RotationEnabled defsecTypes.BoolValue
}

package kms

import "github.com/aquasecurity/defsec/parsers/types"

type KMS struct {
	types.Metadata
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	types.Metadata
	Usage           types.StringValue
	RotationEnabled types.BoolValue
}

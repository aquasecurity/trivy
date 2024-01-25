package kms

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	Metadata defsecTypes.MisconfigMetadata
	Keys     []Key
}

type Key struct {
	Metadata              defsecTypes.MisconfigMetadata
	RotationPeriodSeconds defsecTypes.IntValue
}

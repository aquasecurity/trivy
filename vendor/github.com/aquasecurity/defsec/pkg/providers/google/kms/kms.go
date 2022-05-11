package kms

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	types.Metadata
	Keys []Key
}

type Key struct {
	types.Metadata
	RotationPeriodSeconds types.IntValue
}

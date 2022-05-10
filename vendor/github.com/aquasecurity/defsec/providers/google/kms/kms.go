package kms

import (
	"github.com/aquasecurity/defsec/parsers/types"
)

type KMS struct {
	types.Metadata
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

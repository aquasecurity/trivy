package datalake

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	Metadata         iacTypes.Metadata
	EnableEncryption iacTypes.BoolValue
}

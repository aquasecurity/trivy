package datalake

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	Metadata         defsecTypes.MisconfigMetadata
	EnableEncryption defsecTypes.BoolValue
}

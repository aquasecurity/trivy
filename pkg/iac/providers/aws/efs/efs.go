package efs

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
}

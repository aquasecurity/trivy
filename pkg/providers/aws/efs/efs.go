package efs

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  defsecTypes.MisconfigMetadata
	Encrypted defsecTypes.BoolValue
}

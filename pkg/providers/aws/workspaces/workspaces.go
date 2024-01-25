package workspaces

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	Metadata   defsecTypes.MisconfigMetadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Metadata   defsecTypes.MisconfigMetadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

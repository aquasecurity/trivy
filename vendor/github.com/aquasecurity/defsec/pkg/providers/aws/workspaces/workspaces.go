package workspaces

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	types.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled types.BoolValue
}

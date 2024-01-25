package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Disk struct {
	Metadata   defsecTypes.MisconfigMetadata
	Name       defsecTypes.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	Metadata   defsecTypes.MisconfigMetadata
	RawKey     defsecTypes.BytesValue
	KMSKeyLink defsecTypes.StringValue
}

package kinesis

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	Metadata   defsecTypes.MisconfigMetadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}

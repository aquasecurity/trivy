package kinesis

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}

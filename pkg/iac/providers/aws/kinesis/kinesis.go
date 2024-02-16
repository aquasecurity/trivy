package kinesis

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	Metadata   iacTypes.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
	KMSKeyID iacTypes.StringValue
}

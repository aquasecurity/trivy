package kinesis

import "github.com/aquasecurity/defsec/parsers/types"

type Kinesis struct {
	types.Metadata
	Streams []Stream
}

type Stream struct {
	types.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	types.Metadata
	Type     types.StringValue
	KMSKeyID types.StringValue
}

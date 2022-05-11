package sns

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SNS struct {
	Topics []Topic
}

type Topic struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}

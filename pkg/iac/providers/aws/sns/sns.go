package sns

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata iacTypes.Metadata) *Topic {
	return &Topic{
		Metadata: metadata,
		ARN:      iacTypes.String(arn, metadata),
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: iacTypes.StringDefault("", metadata),
		},
	}
}

type Topic struct {
	Metadata   iacTypes.Metadata
	ARN        iacTypes.StringValue
	Encryption Encryption
}

type Encryption struct {
	Metadata iacTypes.Metadata
	KMSKeyID iacTypes.StringValue
}

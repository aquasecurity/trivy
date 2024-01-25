package sns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata defsecTypes.MisconfigMetadata) *Topic {
	return &Topic{
		Metadata: metadata,
		ARN:      defsecTypes.String(arn, metadata),
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: defsecTypes.StringDefault("", metadata),
		},
	}
}

type Topic struct {
	Metadata   defsecTypes.MisconfigMetadata
	ARN        defsecTypes.StringValue
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	KMSKeyID defsecTypes.StringValue
}

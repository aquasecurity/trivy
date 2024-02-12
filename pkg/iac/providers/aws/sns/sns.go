package sns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata defsecTypes.Metadata) *Topic {
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
	Metadata   defsecTypes.Metadata
	ARN        defsecTypes.StringValue
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	KMSKeyID defsecTypes.StringValue
}

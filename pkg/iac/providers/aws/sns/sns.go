package sns

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SNS struct {
	Topics []Topic
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

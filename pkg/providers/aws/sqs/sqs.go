package sqs

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   defsecTypes.MisconfigMetadata
	QueueURL   defsecTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          defsecTypes.MisconfigMetadata
	KMSKeyID          defsecTypes.StringValue
	ManagedEncryption defsecTypes.BoolValue
}

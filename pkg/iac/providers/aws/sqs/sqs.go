package sqs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   defsecTypes.Metadata
	QueueURL   defsecTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          defsecTypes.Metadata
	KMSKeyID          defsecTypes.StringValue
	ManagedEncryption defsecTypes.BoolValue
}

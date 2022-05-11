package sqs

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	types.Metadata
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	types.Metadata
	KMSKeyID types.StringValue
}

package sqs

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/iam"
)

type SQS struct {
	types.Metadata
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

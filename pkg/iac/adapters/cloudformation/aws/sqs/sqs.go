package sqs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an SQS instance
func Adapt(cfFile parser.FileContext) sqs.SQS {
	return sqs.SQS{
		Queues: getQueues(cfFile),
	}
}

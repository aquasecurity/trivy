package sqs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result sqs.SQS) {

	result.Queues = getQueues(cfFile)
	return result

}

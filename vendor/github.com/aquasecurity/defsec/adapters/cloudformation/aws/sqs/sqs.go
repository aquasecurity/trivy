package sqs

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/sqs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result sqs.SQS) {

	result.Queues = getQueues(cfFile)
	return result

}

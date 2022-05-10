package mq

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result mq.MQ) {

	result.Brokers = getBrokers(cfFile)
	return result
}

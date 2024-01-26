package mq

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an MQ instance
func Adapt(cfFile parser.FileContext) mq.MQ {
	return mq.MQ{
		Brokers: getBrokers(cfFile),
	}
}

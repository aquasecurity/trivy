package mq

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/mq"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts an MQ instance
func Adapt(cfFile parser.FileContext) mq.MQ {
	return mq.MQ{
		Brokers: getBrokers(cfFile),
	}
}

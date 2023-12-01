package mq

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) mq.MQ {
	return mq.MQ{
		Brokers: getBrokers(cfFile),
	}
}

package mq

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/mq"
)

func getBrokers(ctx parser.FileContext) (brokers []mq.Broker) {
	for _, r := range ctx.GetResourceByType("AWS::AmazonMQ::Broker") {

		broker := mq.Broker{
			Metadata:     r.Metadata(),
			PublicAccess: r.GetBoolProperty("PubliclyAccessible"),
			Logging: mq.Logging{
				General: r.GetBoolProperty("Logs.General"),
				Audit:   r.GetBoolProperty("Logs.Audit"),
			},
		}

		brokers = append(brokers, broker)
	}
	return brokers
}

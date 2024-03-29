package mq

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getBrokers(ctx parser.FileContext) (brokers []mq.Broker) {
	for _, r := range ctx.GetResourcesByType("AWS::AmazonMQ::Broker") {

		broker := mq.Broker{
			Metadata:     r.Metadata(),
			PublicAccess: r.GetBoolProperty("PubliclyAccessible"),
			Logging: mq.Logging{
				Metadata: r.Metadata(),
				General:  types.BoolDefault(false, r.Metadata()),
				Audit:    types.BoolDefault(false, r.Metadata()),
			},
		}

		if prop := r.GetProperty("Logs"); prop.IsNotNil() {
			broker.Logging = mq.Logging{
				Metadata: prop.Metadata(),
				General:  prop.GetBoolProperty("General"),
				Audit:    prop.GetBoolProperty("Audit"),
			}
		}

		brokers = append(brokers, broker)
	}
	return brokers
}

package mq

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) mq.MQ {
	return mq.MQ{
		Brokers: adaptBrokers(modules),
	}
}

func adaptBrokers(modules terraform.Modules) []mq.Broker {
	var brokers []mq.Broker
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_mq_broker") {
			brokers = append(brokers, adaptBroker(resource))
		}
	}
	return brokers
}

func adaptBroker(resource *terraform.Block) mq.Broker {

	broker := mq.Broker{
		Metadata:     resource.GetMetadata(),
		PublicAccess: types.BoolDefault(false, resource.GetMetadata()),
		Logging: mq.Logging{
			Metadata: resource.GetMetadata(),
			General:  types.BoolDefault(false, resource.GetMetadata()),
			Audit:    types.BoolDefault(false, resource.GetMetadata()),
		},
	}

	publicAccessAttr := resource.GetAttribute("publicly_accessible")
	broker.PublicAccess = publicAccessAttr.AsBoolValueOrDefault(false, resource)
	if logsBlock := resource.GetBlock("logs"); logsBlock.IsNotNil() {
		broker.Logging.Metadata = logsBlock.GetMetadata()
		auditAttr := logsBlock.GetAttribute("audit")
		broker.Logging.Audit = auditAttr.AsBoolValueOrDefault(false, logsBlock)
		generalAttr := logsBlock.GetAttribute("general")
		broker.Logging.General = generalAttr.AsBoolValueOrDefault(false, logsBlock)
	}

	return broker
}

package msk

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) msk.MSK {
	return msk.MSK{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []msk.Cluster {
	var clusters []msk.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_msk_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) msk.Cluster {
	cluster := msk.Cluster{
		Metadata: resource.GetMetadata(),
		EncryptionInTransit: msk.EncryptionInTransit{
			Metadata:     resource.GetMetadata(),
			ClientBroker: iacTypes.StringDefault("TLS_PLAINTEXT", resource.GetMetadata()),
		},
		EncryptionAtRest: msk.EncryptionAtRest{
			Metadata:  resource.GetMetadata(),
			KMSKeyARN: iacTypes.StringDefault("", resource.GetMetadata()),
			Enabled:   iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		Logging: msk.Logging{
			Metadata: resource.GetMetadata(),
			Broker: msk.BrokerLogging{
				Metadata: resource.GetMetadata(),
				S3: msk.S3Logging{
					Metadata: resource.GetMetadata(),
					Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
				},
				Cloudwatch: msk.CloudwatchLogging{
					Metadata: resource.GetMetadata(),
					Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
				},
				Firehose: msk.FirehoseLogging{
					Metadata: resource.GetMetadata(),
					Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
				},
			},
		},
	}

	if encryptBlock := resource.GetBlock("encryption_info"); encryptBlock.IsNotNil() {
		if encryptionInTransitBlock := encryptBlock.GetBlock("encryption_in_transit"); encryptionInTransitBlock.IsNotNil() {
			cluster.EncryptionInTransit.Metadata = encryptionInTransitBlock.GetMetadata()
			if clientBrokerAttr := encryptionInTransitBlock.GetAttribute("client_broker"); clientBrokerAttr.IsNotNil() {
				cluster.EncryptionInTransit.ClientBroker = clientBrokerAttr.AsStringValueOrDefault("TLS", encryptionInTransitBlock)
			}
		}

		if encryptionAtRestAttr := encryptBlock.GetAttribute("encryption_at_rest_kms_key_arn"); encryptionAtRestAttr.IsNotNil() {
			cluster.EncryptionAtRest.Metadata = encryptionAtRestAttr.GetMetadata()
			cluster.EncryptionAtRest.KMSKeyARN = encryptionAtRestAttr.AsStringValueOrDefault("", encryptBlock)
			cluster.EncryptionAtRest.Enabled = iacTypes.Bool(true, encryptionAtRestAttr.GetMetadata())
		}
	}

	if logBlock := resource.GetBlock("logging_info"); logBlock.IsNotNil() {
		cluster.Logging.Metadata = logBlock.GetMetadata()
		if brokerLogsBlock := logBlock.GetBlock("broker_logs"); brokerLogsBlock.IsNotNil() {
			cluster.Logging.Broker.Metadata = brokerLogsBlock.GetMetadata()
			if brokerLogsBlock.HasChild("s3") {
				if s3Block := brokerLogsBlock.GetBlock("s3"); s3Block.IsNotNil() {
					s3enabledAttr := s3Block.GetAttribute("enabled")
					cluster.Logging.Broker.S3.Metadata = s3Block.GetMetadata()
					cluster.Logging.Broker.S3.Enabled = s3enabledAttr.AsBoolValueOrDefault(false, s3Block)
				}
			}
			if cloudwatchBlock := brokerLogsBlock.GetBlock("cloudwatch_logs"); cloudwatchBlock.IsNotNil() {
				cwEnabledAttr := cloudwatchBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Cloudwatch.Metadata = cloudwatchBlock.GetMetadata()
				cluster.Logging.Broker.Cloudwatch.Enabled = cwEnabledAttr.AsBoolValueOrDefault(false, cloudwatchBlock)
			}
			if firehoseBlock := brokerLogsBlock.GetBlock("firehose"); firehoseBlock.IsNotNil() {
				firehoseEnabledAttr := firehoseBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Firehose.Metadata = firehoseBlock.GetMetadata()
				cluster.Logging.Broker.Firehose.Enabled = firehoseEnabledAttr.AsBoolValueOrDefault(false, firehoseBlock)
			}
		}
	}

	return cluster
}

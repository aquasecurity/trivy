package msk

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/msk"
)

func getClusters(ctx parser.FileContext) (clusters []msk.Cluster) {
	for _, r := range ctx.GetResourceByType("AWS::MSK::Cluster") {

		cluster := msk.Cluster{
			Metadata: r.Metadata(),
			EncryptionInTransit: msk.EncryptionInTransit{
				ClientBroker: r.GetStringProperty("EncryptionInfo.EncryptionInTransit.ClientBroker", "TLS"),
			},
			Logging: msk.Logging{
				Broker: msk.BrokerLogging{
					S3: msk.S3Logging{
						Enabled: r.GetBoolProperty("LoggingInfo.BrokerLogs.S3.Enabled"),
					},
					Cloudwatch: msk.CloudwatchLogging{
						Enabled: r.GetBoolProperty("LoggingInfo.BrokerLogs.CloudWatchLogs.Enabled"),
					},
					Firehose: msk.FirehoseLogging{
						Enabled: r.GetBoolProperty("LoggingInfo.BrokerLogs.Firehose.Enabled"),
					},
				},
			},
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

package msk

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0074",
		Provider:    providers.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-logging",
		Summary:     "Ensure MSK Cluster logging is enabled",
		Impact:      "Without logging it is difficult to trace issues",
		Resolution:  "Enable logging",
		Explanation: `Managed streaming for Kafka can log to Cloud Watch, Kinesis Firehose and S3, at least one of these locations should be logged to`,
		Links: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableLoggingGoodExamples,
			BadExamples:         terraformEnableLoggingBadExamples,
			Links:               terraformEnableLoggingLinks,
			RemediationMarkdown: terraformEnableLoggingRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableLoggingGoodExamples,
			BadExamples:         cloudFormationEnableLoggingBadExamples,
			Links:               cloudFormationEnableLoggingLinks,
			RemediationMarkdown: cloudFormationEnableLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.MSK.Clusters {
			brokerLogging := cluster.Logging.Broker

			if brokerLogging.S3.Enabled.IsTrue() {
				results.AddPassed(&cluster, "S3 Logging is enabled")
				continue
			}

			if brokerLogging.Firehose.Enabled.IsTrue() {
				results.AddPassed(&cluster, "Firehose Logging is enabled")
				continue
			}

			if brokerLogging.Cloudwatch.Enabled.IsTrue() {
				results.AddPassed(&cluster, "Cloudwatch Logging is enabled")
				continue
			}

			results.Add(
				"Cluster does not ship logs to any service.",
				brokerLogging.Cloudwatch.Enabled,
			)
		}
		return
	},
)

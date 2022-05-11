package mq

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableGeneralLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0071",
		Provider:    providers.AWSProvider,
		Service:     "mq",
		ShortCode:   "enable-general-logging",
		Summary:     "MQ Broker should have general logging enabled",
		Impact:      "Without logging it is difficult to trace issues",
		Resolution:  "Enable general logging",
		Explanation: `Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableGeneralLoggingGoodExamples,
			BadExamples:         terraformEnableGeneralLoggingBadExamples,
			Links:               terraformEnableGeneralLoggingLinks,
			RemediationMarkdown: terraformEnableGeneralLoggingRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableGeneralLoggingGoodExamples,
			BadExamples:         cloudFormationEnableGeneralLoggingBadExamples,
			Links:               cloudFormationEnableGeneralLoggingLinks,
			RemediationMarkdown: cloudFormationEnableGeneralLoggingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.Logging.General.IsFalse() {
				results.Add(
					"Broker does not have general logging enabled.",
					broker.Logging.General,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)

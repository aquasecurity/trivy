package mq

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAuditLogging = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0070",
		Provider:    providers.AWSProvider,
		Service:     "mq",
		ShortCode:   "enable-audit-logging",
		Summary:     "MQ Broker should have audit logging enabled",
		Impact:      "Without audit logging it is difficult to trace activity in the MQ broker",
		Resolution:  "Enable audit logging",
		Explanation: `Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableAuditLoggingGoodExamples,
			BadExamples:         terraformEnableAuditLoggingBadExamples,
			Links:               terraformEnableAuditLoggingLinks,
			RemediationMarkdown: terraformEnableAuditLoggingRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableAuditLoggingGoodExamples,
			BadExamples:         cloudFormationEnableAuditLoggingBadExamples,
			Links:               cloudFormationEnableAuditLoggingLinks,
			RemediationMarkdown: cloudFormationEnableAuditLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.Logging.Audit.IsFalse() {
				results.Add(
					"Broker does not have audit logging enabled.",
					broker.Logging.Audit,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)

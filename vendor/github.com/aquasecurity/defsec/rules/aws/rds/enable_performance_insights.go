package rds

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePerformanceInsights = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0133",
		Provider:   providers.AWSProvider,
		Service:    "rds",
		ShortCode:  "enable-performance-insights",
		Summary:    "Enable Performance Insights to detect potential problems",
		Impact:     "Without adequate monitoring, performance related issues may go unreported and potentially lead to compromise.",
		Resolution: "Enable performance insights",
		Explanation: `Enabling Performance insights allows for greater depth in monitoring data.
		
For example, information about active sessions could help diagose a compromise or assist in the investigation`,
		Links: []string{
			"https://aws.amazon.com/rds/performance-insights/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnablePerformanceInsightsGoodExamples,
			BadExamples:         terraformEnablePerformanceInsightsBadExamples,
			Links:               terraformEnablePerformanceInsightsLinks,
			RemediationMarkdown: terraformEnablePerformanceInsightsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnablePerformanceInsightsGoodExamples,
			BadExamples:         cloudFormationEnablePerformanceInsightsBadExamples,
			Links:               cloudFormationEnablePerformanceInsightsLinks,
			RemediationMarkdown: cloudFormationEnablePerformanceInsightsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.IsUnmanaged() {
					continue
				}
				if instance.PerformanceInsights.Enabled.IsFalse() {
					results.Add(
						"Instance does not have performance insights enabled.",
						instance.PerformanceInsights.Enabled,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.PerformanceInsights.Enabled.IsFalse() {
				results.Add(
					"Instance does not have performance insights enabled.",
					instance.PerformanceInsights.Enabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)

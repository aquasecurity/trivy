package ecs

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableContainerInsight = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0034",
		Provider:    providers.AWSProvider,
		Service:     "ecs",
		ShortCode:   "enable-container-insight",
		Summary:     "ECS clusters should have container insights enabled",
		Impact:      "Not all metrics and logs may be gathered for containers when Container Insights isn't enabled",
		Resolution:  "Enable Container Insights",
		Explanation: `Cloudwatch Container Insights provide more metrics and logs for container based applications and micro services.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableContainerInsightGoodExamples,
			BadExamples:         terraformEnableContainerInsightBadExamples,
			Links:               terraformEnableContainerInsightLinks,
			RemediationMarkdown: terraformEnableContainerInsightRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableContainerInsightGoodExamples,
			BadExamples:         cloudFormationEnableContainerInsightBadExamples,
			Links:               cloudFormationEnableContainerInsightLinks,
			RemediationMarkdown: cloudFormationEnableContainerInsightRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.ECS.Clusters {
			if cluster.Settings.ContainerInsightsEnabled.IsFalse() {
				results.Add(
					"Cluster does not have container insights enabled.",
					cluster.Settings.ContainerInsightsEnabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

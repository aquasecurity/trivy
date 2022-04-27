package rds

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePerformanceInsightsEncryption = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0078",
		Provider:   providers.AWSProvider,
		Service:    "rds",
		ShortCode:  "enable-performance-insights-encryption",
		Summary:    "Encryption for RDS Performance Insights should be enabled.",
		Impact:     "Data can be read from the RDS Performance Insights if it is compromised",
		Resolution: "Enable encryption for RDS clusters and instances",
		Explanation: `When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnablePerformanceInsightsEncryptionGoodExamples,
			BadExamples:         terraformEnablePerformanceInsightsEncryptionBadExamples,
			Links:               terraformEnablePerformanceInsightsEncryptionLinks,
			RemediationMarkdown: terraformEnablePerformanceInsightsEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnablePerformanceInsightsEncryptionGoodExamples,
			BadExamples:         cloudFormationEnablePerformanceInsightsEncryptionBadExamples,
			Links:               cloudFormationEnablePerformanceInsightsEncryptionLinks,
			RemediationMarkdown: cloudFormationEnablePerformanceInsightsEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.IsUnmanaged() {
					continue
				}
				if instance.PerformanceInsights.Enabled.IsFalse() {
					continue
				} else if instance.PerformanceInsights.KMSKeyID.IsEmpty() {
					results.Add(
						"Instance has performance insights enabled without encryption.",
						instance.PerformanceInsights.KMSKeyID,
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
				continue
			} else if instance.PerformanceInsights.KMSKeyID.IsEmpty() {
				results.Add(
					"Instance has performance insights enabled without encryption.",
					instance.PerformanceInsights.KMSKeyID,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)

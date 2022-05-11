package dynamodb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableRecovery = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0024",
		Provider:   providers.AWSProvider,
		Service:    "dynamodb",
		ShortCode:  "enable-recovery",
		Summary:    "Point in time recovery should be enabled to protect DynamoDB table",
		Impact:     "Accidental or malicious writes and deletes can't be rolled back",
		Resolution: "Enable point in time recovery",
		Explanation: `DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableRecoveryGoodExamples,
			BadExamples:         terraformEnableRecoveryBadExamples,
			Links:               terraformEnableRecoveryLinks,
			RemediationMarkdown: terraformEnableRecoveryRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.DynamoDB.DAXClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.PointInTimeRecovery.IsFalse() {
				results.Add(
					"Point-in-time recovery is not enabled.",
					cluster.PointInTimeRecovery,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

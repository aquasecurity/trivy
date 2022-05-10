package redshift

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0084",
		Provider:    providers.AWSProvider,
		Service:     "redshift",
		ShortCode:   "encryption-customer-key",
		Summary:     "Redshift clusters should use at rest encryption",
		Impact:      "Data may be leaked if infrastructure is compromised",
		Resolution:  "Enable encryption using CMK",
		Explanation: `Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformEncryptionCustomerKeyBadExamples,
			Links:               terraformEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Redshift.Clusters {
			if cluster.Encryption.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have encryption enabled.",
					cluster.Encryption.Enabled,
				)
			} else if cluster.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not use a customer managed encryption key.",
					cluster.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

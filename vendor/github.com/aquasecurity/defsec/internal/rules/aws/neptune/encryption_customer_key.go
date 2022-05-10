package neptune

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0128",
		Provider:    providers.AWSProvider,
		Service:     "neptune",
		ShortCode:   "encryption-customer-key",
		Summary:     "Neptune encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your Neptune underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformCheckEncryptionCustomerKeyBadExamples,
			Links:               terraformCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationCheckEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not encrypt data with a customer managed key.",
					cluster.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

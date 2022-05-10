package ebs

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0027",
		Provider:    providers.AWSProvider,
		Service:     "ebs",
		ShortCode:   "encryption-customer-key",
		Summary:     "EBS volume encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
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
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, volume := range s.AWS.EBS.Volumes {
			if volume.IsUnmanaged() {
				continue
			}
			if volume.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"EBS volume does not use a customer-managed KMS key.",
					volume.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)

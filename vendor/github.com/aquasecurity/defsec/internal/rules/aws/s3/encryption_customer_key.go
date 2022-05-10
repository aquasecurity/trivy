package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0132",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "encryption-customer-key",
		Summary:     "S3 encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
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
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.Encryption.KMSKeyId.IsEmpty() {
				results.Add(
					"Bucket does not encrypt data with a customer managed key.",
					&bucket.Encryption,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)

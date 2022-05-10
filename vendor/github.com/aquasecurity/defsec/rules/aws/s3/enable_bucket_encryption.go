package s3

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptionIsEnabled = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0088",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-encryption",
		Summary:     "Unencrypted S3 bucket.",
		Impact:      "The bucket objects could be read if compromised",
		Resolution:  "Configure bucket encryption",
		Explanation: `S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
		},

		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableBucketEncryptionGoodExamples,
			BadExamples:         terraformEnableBucketEncryptionBadExamples,
			Links:               terraformEnableBucketEncryptionLinks,
			RemediationMarkdown: terraformEnableBucketEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableBucketEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableBucketEncryptionBadExamples,
			Links:               cloudFormationEnableBucketEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableBucketEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.Encryption.Enabled.IsFalse() {
				results.Add(
					"Bucket does not have encryption enabled",
					bucket.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&bucket, "Bucket encryption correctly configured")
			}
		}
		return results
	},
)

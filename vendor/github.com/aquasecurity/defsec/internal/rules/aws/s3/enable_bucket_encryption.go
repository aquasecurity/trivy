package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEncryptionIsEnabled = rules.Register(
	scan.Rule{
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

		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableBucketEncryptionGoodExamples,
			BadExamples:         terraformEnableBucketEncryptionBadExamples,
			Links:               terraformEnableBucketEncryptionLinks,
			RemediationMarkdown: terraformEnableBucketEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableBucketEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableBucketEncryptionBadExamples,
			Links:               cloudFormationEnableBucketEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableBucketEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
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

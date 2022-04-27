package s3

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckLoggingIsEnabled = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0089",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-logging",
		Summary:     "S3 Bucket does not have logging enabled.",
		Explanation: "Buckets should have logging enabled so that access can be audited.",
		Impact:      "There is no way to determine the access to this bucket",
		Resolution:  "Add a logging block to the resource to enable access logging",
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableBucketLoggingGoodExamples,
			BadExamples:         terraformEnableBucketLoggingBadExamples,
			Links:               terraformEnableBucketLoggingLinks,
			RemediationMarkdown: terraformEnableBucketLoggingRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableBucketLoggingGoodExamples,
			BadExamples:         cloudFormationEnableBucketLoggingBadExamples,
			Links:               cloudFormationEnableBucketLoggingLinks,
			RemediationMarkdown: cloudFormationEnableBucketLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if !bucket.Logging.Enabled.IsTrue() && bucket.ACL.NotEqualTo("log-delivery-write") {
				results.Add(
					"Bucket does not have logging enabled",
					bucket.Logging.Enabled,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)

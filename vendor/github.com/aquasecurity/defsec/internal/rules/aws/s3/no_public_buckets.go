package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckPublicBucketsAreRestricted = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0093",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "no-public-buckets",
		Summary:     "S3 Access block should restrict public bucket to limit access",
		Impact:      "Public buckets can be accessed by anyone",
		Resolution:  "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)",
		Explanation: `S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicBucketsGoodExamples,
			BadExamples:         terraformNoPublicBucketsBadExamples,
			Links:               terraformNoPublicBucketsLinks,
			RemediationMarkdown: terraformNoPublicBucketsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicBucketsGoodExamples,
			BadExamples:         cloudFormationNoPublicBucketsBadExamples,
			Links:               cloudFormationNoPublicBucketsLinks,
			RemediationMarkdown: cloudFormationNoPublicBucketsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not restricting public buckets", &bucket)
			} else if bucket.PublicAccessBlock.RestrictPublicBuckets.IsFalse() {
				results.Add(
					"Public access block does not restrict public buckets",
					bucket.PublicAccessBlock.RestrictPublicBuckets,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)

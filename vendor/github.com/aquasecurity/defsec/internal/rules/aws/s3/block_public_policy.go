package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckPublicPoliciesAreBlocked = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0087",
		Provider:   providers.AWSProvider,
		Service:    "s3",
		ShortCode:  "block-public-policy",
		Summary:    "S3 Access block should block public policy",
		Impact:     "Users could put a policy that allows public access",
		Resolution: "Prevent policies that allow public access being PUT",
		Explanation: `
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
`,

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformBlockPublicPolicyGoodExamples,
			BadExamples:         terraformBlockPublicPolicyBadExamples,
			Links:               terraformBlockPublicPolicyLinks,
			RemediationMarkdown: terraformBlockPublicPolicyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationBlockPublicPolicyGoodExamples,
			BadExamples:         cloudFormationBlockPublicPolicyBadExamples,
			Links:               cloudFormationBlockPublicPolicyLinks,
			RemediationMarkdown: cloudFormationBlockPublicPolicyRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not blocking public policies", &bucket)
			} else if bucket.PublicAccessBlock.BlockPublicPolicy.IsFalse() {
				results.Add(
					"Public access block does not block public policies",
					bucket.PublicAccessBlock.BlockPublicPolicy,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)

package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckForPublicACL = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0092",
		Provider:  providers.AWSProvider,
		Service:   "s3",
		ShortCode: "no-public-access-with-acl",
		Summary:   "S3 Buckets not publicly accessible through ACL.",
		Explanation: `
Buckets should not have ACLs that allow public access
`,
		Impact:     "Public access to the bucket can lead to data leakage",
		Resolution: "Don't use canned ACLs or switch to private acl",

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessWithAclGoodExamples,
			BadExamples:         terraformNoPublicAccessWithAclBadExamples,
			Links:               terraformNoPublicAccessWithAclLinks,
			RemediationMarkdown: terraformNoPublicAccessWithAclRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessWithAclGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessWithAclBadExamples,
			Links:               cloudFormationNoPublicAccessWithAclLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessWithAclRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.HasPublicExposureACL() {
				if bucket.ACL.EqualTo("authenticated-read") {
					results.Add(
						"Bucket is exposed to all AWS accounts via ACL.",
						bucket.ACL,
					)
				} else {
					results.Add(
						fmt.Sprintf("Bucket has a public ACL: '%s'.", bucket.ACL.Value()),
						bucket.ACL,
					)
				}
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)

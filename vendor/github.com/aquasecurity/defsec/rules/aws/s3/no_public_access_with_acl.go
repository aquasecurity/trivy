package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckForPublicACL = rules.Register(
	rules.Rule{
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
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessWithAclGoodExamples,
			BadExamples:         terraformNoPublicAccessWithAclBadExamples,
			Links:               terraformNoPublicAccessWithAclLinks,
			RemediationMarkdown: terraformNoPublicAccessWithAclRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessWithAclGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessWithAclBadExamples,
			Links:               cloudFormationNoPublicAccessWithAclLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessWithAclRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
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

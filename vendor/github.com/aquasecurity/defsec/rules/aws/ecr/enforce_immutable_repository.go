package ecr

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceImmutableRepository = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0031",
		Provider:   providers.AWSProvider,
		Service:    "ecr",
		ShortCode:  "enforce-immutable-repository",
		Summary:    "ECR images tags shouldn't be mutable.",
		Impact:     "Image tags could be overwritten with compromised images",
		Resolution: "Only use immutable images in ECR",
		Explanation: `ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>`,
		Links: []string{
			"https://sysdig.com/blog/toctou-tag-mutability/",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnforceImmutableRepositoryGoodExamples,
			BadExamples:         terraformEnforceImmutableRepositoryBadExamples,
			Links:               terraformEnforceImmutableRepositoryLinks,
			RemediationMarkdown: terraformEnforceImmutableRepositoryRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnforceImmutableRepositoryGoodExamples,
			BadExamples:         cloudFormationEnforceImmutableRepositoryBadExamples,
			Links:               cloudFormationEnforceImmutableRepositoryLinks,
			RemediationMarkdown: cloudFormationEnforceImmutableRepositoryRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.ImageTagsImmutable.IsFalse() {
				results.Add(
					"Repository tags are mutable.",
					repo.ImageTagsImmutable,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)

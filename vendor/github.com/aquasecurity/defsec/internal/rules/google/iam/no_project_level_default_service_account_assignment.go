package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoProjectLevelDefaultServiceAccountAssignment = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0006",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-project-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Default service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoProjectLevelDefaultServiceAccountAssignmentGoodExamples,
			BadExamples:         terraformNoProjectLevelDefaultServiceAccountAssignmentBadExamples,
			Links:               terraformNoProjectLevelDefaultServiceAccountAssignmentLinks,
			RemediationMarkdown: terraformNoProjectLevelDefaultServiceAccountAssignmentRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, binding := range project.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if binding.IncludesDefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at project level.",
						binding.IncludesDefaultServiceAccount,
					)
				} else {
					for _, member := range binding.Members {
						if isMemberDefaultServiceAccount(member.Value()) {
							results.Add(
								"Role is assigned to a default service account at project level.",
								member,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}
			for _, member := range project.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.DefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at project level.",
						member.DefaultServiceAccount,
					)
				} else if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at project level.",
						member.Member,
					)
				} else {
					results.AddPassed(&member)
				}

			}
		}
		return
	},
)

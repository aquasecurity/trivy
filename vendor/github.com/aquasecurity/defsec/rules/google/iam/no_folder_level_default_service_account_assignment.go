package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoFolderLevelDefaultServiceAccountAssignment = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0004",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-folder-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Default service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoFolderLevelDefaultServiceAccountAssignmentGoodExamples,
			BadExamples:         terraformNoFolderLevelDefaultServiceAccountAssignmentBadExamples,
			Links:               terraformNoFolderLevelDefaultServiceAccountAssignmentLinks,
			RemediationMarkdown: terraformNoFolderLevelDefaultServiceAccountAssignmentRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, folder := range s.Google.IAM.AllFolders() {
			for _, member := range folder.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.DefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at folder level.",
						member.DefaultServiceAccount,
					)
				} else if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at folder level.",
						member.Member,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range folder.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if binding.IncludesDefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at folder level.",
						binding.IncludesDefaultServiceAccount,
					)
					continue
				}
				for _, member := range binding.Members {
					if isMemberDefaultServiceAccount(member.Value()) {
						results.Add(
							"Role is assigned to a default service account at folder level.",
							member,
						)
					} else {
						results.AddPassed(member)
					}
				}
			}

		}
		return
	},
)

func isMemberDefaultServiceAccount(member string) bool {
	return strings.HasSuffix(member, "-compute@developer.gserviceaccount.com") || strings.HasSuffix(member, "@appspot.gserviceaccount.com")
}

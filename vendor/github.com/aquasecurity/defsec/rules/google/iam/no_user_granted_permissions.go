package iam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoUserGrantedPermissions = rules.Register(
	rules.Rule{
		AVDID:      "AVD-GCP-0003",
		Provider:   providers.GoogleProvider,
		Service:    "iam",
		ShortCode:  "no-user-granted-permissions",
		Summary:    "IAM granted directly to user.",
		Impact:     "Users shouldn't have permissions granted to them directly",
		Resolution: "Roles should be granted permissions and assigned to users",
		Explanation: `Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user. 

Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.

Permissions should be granted on roles, groups, services accounts instead.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/overview#permissions",
			"https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoUserGrantedPermissionsGoodExamples,
			BadExamples:         terraformNoUserGrantedPermissionsBadExamples,
			Links:               terraformNoUserGrantedPermissionsLinks,
			RemediationMarkdown: terraformNoUserGrantedPermissionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, member := range project.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("user:") {
					results.Add(
						"Permissions are granted directly to a user.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range project.Bindings {
				for _, member := range binding.Members {
					if member.StartsWith("user:") {
						results.Add(
							"Permissions are granted directly to a user.",
							binding.Role,
						)
					} else {
						results.AddPassed(member)
					}

				}
			}
		}

		for _, folder := range s.Google.IAM.AllFolders() {
			for _, member := range folder.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("user:") {
					results.Add(
						"Permissions are granted directly to a user.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range folder.Bindings {
				for _, member := range binding.Members {
					if member.StartsWith("user:") {
						results.Add(
							"Permissions are granted directly to a user.",
							binding.Role,
						)
					} else {
						results.AddPassed(member)
					}

				}
			}
		}

		for _, org := range s.Google.IAM.Organizations {
			for _, member := range org.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("user:") {
					results.Add(
						"Permissions are granted directly to a user.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range org.Bindings {
				for _, member := range binding.Members {
					if member.StartsWith("user:") {
						results.Add(
							"Permissions are granted directly to a user.",
							binding.Role,
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

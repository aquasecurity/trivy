package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoProjectLevelServiceAccountImpersonation = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0011",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-project-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the project level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of project-level, if required",
		Explanation: `Users with service account access at project level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoProjectLevelServiceAccountImpersonationGoodExamples,
			BadExamples:         terraformNoProjectLevelServiceAccountImpersonationBadExamples,
			Links:               terraformNoProjectLevelServiceAccountImpersonationLinks,
			RemediationMarkdown: terraformNoProjectLevelServiceAccountImpersonationRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, member := range project.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at project level.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}
			}
			for _, binding := range project.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at project level.",
						binding.Role,
					)
				} else {
					results.AddPassed(&binding)
				}

			}
		}
		return
	},
)

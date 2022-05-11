package authorization

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckLimitRoleActions = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0030",
		Provider:    providers.AzureProvider,
		Service:     "authorization",
		ShortCode:   "limit-role-actions",
		Summary:     "Roles limited to the required actions",
		Impact:      "Open permissions for subscriptions could result in an easily compromisable account",
		Resolution:  "Use targeted permissions for roles",
		Explanation: `The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformLimitRoleActionsGoodExamples,
			BadExamples:         terraformLimitRoleActionsBadExamples,
			Links:               terraformLimitRoleActionsLinks,
			RemediationMarkdown: terraformLimitRoleActionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, roleDef := range s.Azure.Authorization.RoleDefinitions {
			for _, perm := range roleDef.Permissions {
				for _, action := range perm.Actions {
					if action.Contains("*") {
						for _, scope := range roleDef.AssignableScopes {
							if scope.EqualTo("/") {
								results.Add(
									"Role definition uses wildcard action with all scopes.",
									action,
								)
							} else {
								results.AddPassed(&perm)
							}
						}

					}
				}
			}
		}
		return
	},
)

package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireSymbolsInPasswords = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0060",
		Provider:    providers.AWSProvider,
		Service:     "iam",
		ShortCode:   "require-symbols-in-passwords",
		Summary:     "IAM Password policy should have requirement for at least one symbol in the password.",
		Impact:      "Short, simple passwords are easier to compromise",
		Resolution:  "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords content including a symbol.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireSymbolsInPasswordsGoodExamples,
			BadExamples:         terraformRequireSymbolsInPasswordsBadExamples,
			Links:               terraformRequireSymbolsInPasswordsLinks,
			RemediationMarkdown: terraformRequireSymbolsInPasswordsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.RequireSymbols.IsFalse() {
			results.Add(
				"Password policy does not require symbols.",
				policy.RequireSymbols,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)

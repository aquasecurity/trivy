package iam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRequireSymbolsInPasswords = rules.Register(
	rules.Rule{
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
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformRequireSymbolsInPasswordsGoodExamples,
			BadExamples:         terraformRequireSymbolsInPasswordsBadExamples,
			Links:               terraformRequireSymbolsInPasswordsLinks,
			RemediationMarkdown: terraformRequireSymbolsInPasswordsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
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

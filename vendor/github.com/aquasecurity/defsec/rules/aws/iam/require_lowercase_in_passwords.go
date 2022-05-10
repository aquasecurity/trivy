package iam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRequireLowercaseInPasswords = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0058",
		Provider:    providers.AWSProvider,
		Service:     "iam",
		ShortCode:   "require-lowercase-in-passwords",
		Summary:     "IAM Password policy should have requirement for at least one lowercase character.",
		Impact:      "Short, simple passwords are easier to compromise",
		Resolution:  "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords content including at least one lowercase character.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformRequireLowercaseInPasswordsGoodExamples,
			BadExamples:         terraformRequireLowercaseInPasswordsBadExamples,
			Links:               terraformRequireLowercaseInPasswordsLinks,
			RemediationMarkdown: terraformRequireLowercaseInPasswordsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.RequireLowercase.IsFalse() {
			results.Add(
				"Password policy does not require lowercase characters.",
				policy.RequireLowercase,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)

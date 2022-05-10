package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckSetMinimumPasswordLength = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0063",
		Provider:   providers.AWSProvider,
		Service:    "iam",
		ShortCode:  "set-minimum-password-length",
		Summary:    "IAM Password policy should have minimum password length of 14 or more characters.",
		Impact:     "Short, simple passwords are easier to compromise",
		Resolution: "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSetMinimumPasswordLengthGoodExamples,
			BadExamples:         terraformSetMinimumPasswordLengthBadExamples,
			Links:               terraformSetMinimumPasswordLengthLinks,
			RemediationMarkdown: terraformSetMinimumPasswordLengthRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.MinimumLength.LessThan(14) {
			results.Add(
				"Password policy has a minimum password length of less than 14 characters.",
				policy.MinimumLength,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)

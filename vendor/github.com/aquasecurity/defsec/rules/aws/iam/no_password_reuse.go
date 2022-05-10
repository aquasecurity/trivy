package iam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPasswordReuse = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0056",
		Provider:   providers.AWSProvider,
		Service:    "iam",
		ShortCode:  "no-password-reuse",
		Summary:    "IAM Password policy should prevent password reuse.",
		Impact:     "Password reuse increase the risk of compromised passwords being abused",
		Resolution: "Prevent password reuse in the policy",
		Explanation: `IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPasswordReuseGoodExamples,
			BadExamples:         terraformNoPasswordReuseBadExamples,
			Links:               terraformNoPasswordReuseLinks,
			RemediationMarkdown: terraformNoPasswordReuseRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {

		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.ReusePreventionCount.LessThan(5) {
			results.Add(
				"Password policy allows reuse of recent passwords.",
				policy.ReusePreventionCount,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)

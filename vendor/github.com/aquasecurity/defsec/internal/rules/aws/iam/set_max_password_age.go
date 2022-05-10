package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckSetMaxPasswordAge = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0062",
		Provider:   providers.AWSProvider,
		Service:    "iam",
		ShortCode:  "set-max-password-age",
		Summary:    "IAM Password policy should have expiry less than or equal to 90 days.",
		Impact:     "Long life password increase the likelihood of a password eventually being compromised",
		Resolution: "Limit the password duration with an expiry in the policy",
		Explanation: `IAM account password policies should have a maximum age specified. 
		
The account password policy should be set to expire passwords after 90 days or less.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSetMaxPasswordAgeGoodExamples,
			BadExamples:         terraformSetMaxPasswordAgeBadExamples,
			Links:               terraformSetMaxPasswordAgeLinks,
			RemediationMarkdown: terraformSetMaxPasswordAgeRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.MaxAgeDays.GreaterThan(90) {
			results.Add(
				"Password policy allows a maximum password age of greater than 90 days.",
				policy.MaxAgeDays,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)

package iam

import (
	"strings"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckEnforceMFA = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0123",
		Provider:   providers.AWSProvider,
		Service:    "iam",
		ShortCode:  "enforce-mfa",
		Summary:    "IAM Groups should have MFA enforcement activated.",
		Impact:     "User accounts are more vulnerable to compromise without multi factor authentication activated",
		Resolution: "Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced",
		Explanation: `
IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnforceMfaGoodExamples,
			BadExamples:         terraformEnforceMfaBadExamples,
			Links:               terraformEnforceMfaLinks,
			RemediationMarkdown: terraformEnforceMfaRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {

		for _, group := range s.AWS.IAM.Groups {
			var mfaEnforced bool
			for _, policy := range group.Policies {
				document := policy.Document.Parsed
				statements, _ := document.Statements()
				for _, statement := range statements {
					conditions, _ := statement.Conditions()
					for _, condition := range conditions {
						key, _ := condition.Key()
						if strings.EqualFold(key, "aws:MultiFactorAuthPresent") {
							mfaEnforced = true
							break
						}
					}
				}
			}
			if !mfaEnforced {
				results.Add("Multi-Factor authentication is not enforced for group", &group)
			}
		}

		return
	},
)

package kms

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/kms"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAutoRotateKeys = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0065",
		Provider:    providers.AWSProvider,
		Service:     "kms",
		ShortCode:   "auto-rotate-keys",
		Summary:     "A KMS key is not configured to auto-rotate.",
		Impact:      "Long life KMS keys increase the attack surface when compromised",
		Resolution:  "Configure KMS key to auto rotate",
		Explanation: `You should configure your KMS keys to auto rotate to maintain security and defend against compromise.`,
		Links: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformAutoRotateKeysGoodExamples,
			BadExamples:         terraformAutoRotateKeysBadExamples,
			Links:               terraformAutoRotateKeysLinks,
			RemediationMarkdown: terraformAutoRotateKeysRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, key := range s.AWS.KMS.Keys {
			if key.Usage.EqualTo(kms.KeyUsageSignAndVerify) {
				continue
			}
			if key.RotationEnabled.IsFalse() {
				results.Add(
					"Key does not have rotation enabled.",
					key.RotationEnabled,
				)
			} else {
				results.AddPassed(&key)
			}
		}
		return
	},
)

package ssm

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/ssm"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSecretUseCustomerKey = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0098",
		Provider:    providers.AWSProvider,
		Service:     "ssm",
		ShortCode:   "secret-use-customer-key",
		Summary:     "Secrets Manager should use customer managed keys",
		Impact:      "Using AWS managed keys reduces the flexibility and control over the encryption key",
		Resolution:  "Use customer managed keys",
		Explanation: `Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.`,
		Links: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformSecretUseCustomerKeyGoodExamples,
			BadExamples:         terraformSecretUseCustomerKeyBadExamples,
			Links:               terraformSecretUseCustomerKeyLinks,
			RemediationMarkdown: terraformSecretUseCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationSecretUseCustomerKeyGoodExamples,
			BadExamples:         cloudFormationSecretUseCustomerKeyBadExamples,
			Links:               cloudFormationSecretUseCustomerKeyLinks,
			RemediationMarkdown: cloudFormationSecretUseCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, secret := range s.AWS.SSM.Secrets {
			if secret.KMSKeyID.IsEmpty() {
				results.Add(
					"Secret is not encrypted with a customer managed key.",
					secret.KMSKeyID,
				)
			} else if secret.KMSKeyID.EqualTo(ssm.DefaultKMSKeyID) {
				results.Add(
					"Secret explicitly uses the default key.",
					secret.KMSKeyID,
				)
			} else {
				results.AddPassed(&secret)
			}
		}
		return
	},
)

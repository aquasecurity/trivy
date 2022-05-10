package secrets

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckNotExposed = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GEN-0004",
		Provider:    providers.GeneralProvider,
		Service:     "secrets",
		ShortCode:   "no-plaintext-exposure",
		Summary:     "Secret/sensitive data should not be exposed in plaintext.",
		Impact:      "Sensitive data can be leaked to unauthorised people or systems.",
		Resolution:  "Remove plaintext secrets and encrypt them within a secrets manager instead.",
		Explanation: `Plaintext secrets kept in source code or similar media mean sensitive data is exposed to any users/systems with access to the source code.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPlaintextExposureGoodExamples,
			BadExamples:         terraformNoPlaintextExposureBadExamples,
			Links:               terraformNoPlaintextExposureLinks,
			RemediationMarkdown: terraformNoPlaintextExposureRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	nil,
)

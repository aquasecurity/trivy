package sam

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableTableEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0121",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-table-encryption",
		Summary:     "SAM Simple table must have server side encryption enabled.",
		Impact:      "Data stored in the table that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable server side encryption",
		Explanation: `Encryption should be enabled at all available levels to ensure that data is protected if compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification",
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableTableEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableTableEncryptionBadExamples,
			Links:               cloudFormationEnableTableEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableTableEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, table := range s.AWS.SAM.SimpleTables {
			if table.SSESpecification.Enabled.IsFalse() {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					table.SSESpecification.Enabled,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)

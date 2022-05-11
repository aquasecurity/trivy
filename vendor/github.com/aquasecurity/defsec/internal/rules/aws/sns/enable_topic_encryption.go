package sns

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableTopicEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0095",
		Provider:    providers.AWSProvider,
		Service:     "sns",
		ShortCode:   "enable-topic-encryption",
		Summary:     "Unencrypted SNS topic.",
		Impact:      "The SNS topic messages could be read if compromised",
		Resolution:  "Turn on SNS Topic encryption",
		Explanation: `Topics should be encrypted to protect their contents.`,
		Links: []string{
			"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableTopicEncryptionGoodExamples,
			BadExamples:         terraformEnableTopicEncryptionBadExamples,
			Links:               terraformEnableTopicEncryptionLinks,
			RemediationMarkdown: terraformEnableTopicEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableTopicEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableTopicEncryptionBadExamples,
			Links:               cloudFormationEnableTopicEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableTopicEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, topic := range s.AWS.SNS.Topics {
			if topic.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Topic does not have encryption enabled.",
					topic.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&topic)
			}
		}
		return
	},
)

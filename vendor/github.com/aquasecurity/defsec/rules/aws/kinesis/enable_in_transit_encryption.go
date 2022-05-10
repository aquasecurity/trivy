package kinesis

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0064",
		Provider:    providers.AWSProvider,
		Service:     "kinesis",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Kinesis stream is unencrypted.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.`,
		Links: []string{
			"https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, stream := range s.AWS.Kinesis.Streams {
			if stream.Encryption.Type.NotEqualTo(kinesis.EncryptionTypeKMS) {
				results.Add(
					"Stream does not use KMS encryption.",
					stream.Encryption.Type,
				)
			} else if stream.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Stream does not use a custom-managed KMS key.",
					stream.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&stream)
			}
		}
		return
	},
)

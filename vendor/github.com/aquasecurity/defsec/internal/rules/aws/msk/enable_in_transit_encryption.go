package msk

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0073",
		Provider:    providers.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "A MSK cluster allows unencrypted data in transit.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.MSK.Clusters {
			if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk.ClientBrokerEncryptionPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk.ClientBrokerEncryptionTLSOrPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)

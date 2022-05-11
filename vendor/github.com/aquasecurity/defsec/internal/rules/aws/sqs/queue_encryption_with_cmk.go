package sqs

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckQueueEncryptionUsesCMK = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0135",
		Provider:    providers.AWSProvider,
		Service:     "sqs",
		ShortCode:   "queue-encryption-use-cmk",
		Summary:     "SQS queue should be encrypted with a CMK.",
		Impact:      "The SQS queue messages could be read if compromised. Key management is very limited when using default keys.",
		Resolution:  "Encrypt SQS Queue with a customer-managed key",
		Explanation: `Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformQueueEncryptionUsesCMKGoodExamples,
			BadExamples:         terraformQueueEncryptionUsesCMKBadExamples,
			Links:               terraformQueueEncryptionUsesCMKLinks,
			RemediationMarkdown: terraformQueueEncryptionUsesCMKRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationQueueEncryptionUsesCMKGoodExamples,
			BadExamples:         cloudFormationQueueEncryptionUsesCMKBadExamples,
			Links:               cloudFormationQueueEncryptionUsesCMKLinks,
			RemediationMarkdown: cloudFormationQueueEncryptionUsesCMKRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			if queue.IsUnmanaged() {
				continue
			}
			if queue.Encryption.KMSKeyID.EqualTo("alias/aws/sqs") {
				results.Add(
					"Queue is not encrypted with a customer managed key.",
					queue.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&queue)
			}
		}
		return
	},
)

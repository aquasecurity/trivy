package sqs

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableQueueEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0096",
		Provider:    providers.AWSProvider,
		Service:     "sqs",
		ShortCode:   "enable-queue-encryption",
		Summary:     "Unencrypted SQS queue.",
		Impact:      "The SQS queue messages could be read if compromised",
		Resolution:  "Turn on SQS Queue encryption",
		Explanation: `Queues should be encrypted to protect queue contents.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableQueueEncryptionGoodExamples,
			BadExamples:         terraformEnableQueueEncryptionBadExamples,
			Links:               terraformEnableQueueEncryptionLinks,
			RemediationMarkdown: terraformEnableQueueEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableQueueEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableQueueEncryptionBadExamples,
			Links:               cloudFormationEnableQueueEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableQueueEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			if queue.IsUnmanaged() {
				continue
			}
			if queue.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Queue is not encrypted",
					queue.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&queue)
			}
		}
		return
	},
)

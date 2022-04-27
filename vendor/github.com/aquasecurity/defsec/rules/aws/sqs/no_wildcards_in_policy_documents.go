package sqs

import (
	"strings"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
	"github.com/liamg/iamgo"
)

var CheckNoWildcardsInPolicyDocuments = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0097",
		Provider:   providers.AWSProvider,
		Service:    "sqs",
		ShortCode:  "no-wildcards-in-policy-documents",
		Summary:    "AWS SQS policy document has wildcard action statement.",
		Impact:     "SQS policies with wildcard actions allow more that is required",
		Resolution: "Keep policy scope to the minimum that is required to be effective",
		Explanation: `SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoWildcardsInPolicyDocumentsGoodExamples,
			BadExamples:         terraformNoWildcardsInPolicyDocumentsBadExamples,
			Links:               terraformNoWildcardsInPolicyDocumentsLinks,
			RemediationMarkdown: terraformNoWildcardsInPolicyDocumentsRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationNoWildcardsInPolicyDocumentsGoodExamples,
			BadExamples:         cloudFormationNoWildcardsInPolicyDocumentsBadExamples,
			Links:               cloudFormationNoWildcardsInPolicyDocumentsLinks,
			RemediationMarkdown: cloudFormationNoWildcardsInPolicyDocumentsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			for _, policyDoc := range queue.Policies {
				var fail bool
				policy := policyDoc.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					effect, _ := statement.Effect()
					if effect != iamgo.EffectAllow {
						continue
					}
					actions, r := statement.Actions()
					for _, action := range actions {
						action = strings.ToLower(action)
						if action == "*" || action == "sqs:*" {
							fail = true
							results.Add(
								"Queue policy does not restrict actions to a known set.",
								policyDoc.Document.MetadataFromIamGo(statement.Range(), r),
							)
							break
						}
					}
				}
				if !fail {
					results.AddPassed(&queue)
				}
			}
		}
		return
	},
)

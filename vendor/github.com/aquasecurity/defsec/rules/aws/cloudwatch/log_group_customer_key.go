package cloudwatch

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckLogGroupCustomerKey = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0017",
		Provider:    providers.AWSProvider,
		Service:     "cloudwatch",
		ShortCode:   "log-group-customer-key",
		Summary:     "CloudWatch log groups should be encrypted using CMK",
		Impact:      "Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs.",
		Resolution:  "Enable CMK encryption of CloudWatch Log Groups",
		Explanation: `CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformLogGroupCustomerKeyGoodExamples,
			BadExamples:         terraformLogGroupCustomerKeyBadExamples,
			Links:               terraformLogGroupCustomerKeyLinks,
			RemediationMarkdown: terraformLogGroupCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationLogGroupCustomerKeyGoodExamples,
			BadExamples:         cloudFormationLogGroupCustomerKeyBadExamples,
			Links:               cloudFormationLogGroupCustomerKeyLinks,
			RemediationMarkdown: cloudFormationLogGroupCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.AWS.CloudWatch.LogGroups {
			if group.KMSKeyID.IsEmpty() {
				results.Add(
					"Log group is not encrypted.",
					group.KMSKeyID,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)

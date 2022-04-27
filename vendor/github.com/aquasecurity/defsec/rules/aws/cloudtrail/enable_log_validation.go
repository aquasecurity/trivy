package cloudtrail

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogValidation = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0016",
		Provider:    providers.AWSProvider,
		Service:     "cloudtrail",
		ShortCode:   "enable-log-validation",
		Summary:     "Cloudtrail log validation should be enabled to prevent tampering of log data",
		Impact:      "Illicit activity could be removed from the logs",
		Resolution:  "Turn on log validation for Cloudtrail",
		Explanation: `Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableLogValidationGoodExamples,
			BadExamples:         terraformEnableLogValidationBadExamples,
			Links:               terraformEnableLogValidationLinks,
			RemediationMarkdown: terraformEnableLogValidationRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableLogValidationGoodExamples,
			BadExamples:         cloudFormationEnableLogValidationBadExamples,
			Links:               cloudFormationEnableLogValidationLinks,
			RemediationMarkdown: cloudFormationEnableLogValidationRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.EnableLogFileValidation.IsFalse() {
				results.Add(
					"Trail does not have log validation enabled.",
					trail.EnableLogFileValidation,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)

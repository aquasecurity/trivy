package ecr

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableImageScans = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0030",
		Provider:    providers.AWSProvider,
		Service:     "ecr",
		ShortCode:   "enable-image-scans",
		Summary:     "ECR repository has image scans disabled.",
		Impact:      "The ability to scan images is not being used and vulnerabilities will not be highlighted",
		Resolution:  "Enable ECR image scanning",
		Explanation: `Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformEnableImageScansGoodExamples,
			BadExamples:         terraformEnableImageScansBadExamples,
			Links:               terraformEnableImageScansLinks,
			RemediationMarkdown: terraformEnableImageScansRemediationMarkdown,
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableImageScansGoodExamples,
			BadExamples:         cloudFormationEnableImageScansBadExamples,
			Links:               cloudFormationEnableImageScansLinks,
			RemediationMarkdown: cloudFormationEnableImageScansRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.ImageScanning.ScanOnPush.IsFalse() {
				results.Add(
					"Image scanning is not enabled.",
					repo.ImageScanning.ScanOnPush,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)

package lambda

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRestrictSourceArn = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0067",
		Provider:   providers.AWSProvider,
		Service:    "lambda",
		ShortCode:  "restrict-source-arn",
		Summary:    "Ensure that lambda function permission has a source arn specified",
		Impact:     "Not providing the source ARN allows any resource from principal, even from other accounts",
		Resolution: "Always provide a source arn for Lambda permissions",
		Explanation: `When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to. 

Without this, any resource from principal will be granted permission – even if that resource is from another account. 

For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRestrictSourceArnGoodExamples,
			BadExamples:         terraformRestrictSourceArnBadExamples,
			Links:               terraformRestrictSourceArnLinks,
			RemediationMarkdown: terraformRestrictSourceArnRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationRestrictSourceArnGoodExamples,
			BadExamples:         cloudFormationRestrictSourceArnBadExamples,
			Links:               cloudFormationRestrictSourceArnLinks,
			RemediationMarkdown: cloudFormationRestrictSourceArnRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, function := range s.AWS.Lambda.Functions {
			for _, permission := range function.Permissions {
				if !permission.Principal.EndsWith(".amazonaws.com") {
					continue
				}
				if permission.SourceARN.IsEmpty() {
					results.Add(
						"Lambda permission lacks source ARN for *.amazonaws.com principal.",
						permission.SourceARN,
					)
				} else {
					results.AddPassed(&function)
				}
			}
		}
		return
	},
)

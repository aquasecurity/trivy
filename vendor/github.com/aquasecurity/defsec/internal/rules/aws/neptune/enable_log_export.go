package neptune

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableLogExport = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0075",
		Provider:    providers.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-log-export",
		Summary:     "Neptune logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to Neptune",
		Resolution:  "Enable export logs",
		Explanation: `Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableLogExportGoodExamples,
			BadExamples:         terraformEnableLogExportBadExamples,
			Links:               terraformEnableLogExportLinks,
			RemediationMarkdown: terraformEnableLogExportRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableLogExportGoodExamples,
			BadExamples:         cloudFormationEnableLogExportBadExamples,
			Links:               cloudFormationEnableLogExportLinks,
			RemediationMarkdown: cloudFormationEnableLogExportRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.Logging.Audit.IsFalse() {
				results.Add(
					"Cluster does not have audit logging enabled.",
					cluster.Logging.Audit,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

package documentdb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableLogExport = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0020",
		Provider:    providers.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-log-export",
		Summary:     "DocumentDB logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to the DocumentDB",
		Resolution:  "Enable export logs",
		Explanation: `Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html",
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
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			var hasAudit bool
			var hasProfiler bool

			for _, log := range cluster.EnabledLogExports {
				if log.EqualTo(documentdb.LogExportAudit) {
					hasAudit = true
				}
				if log.EqualTo(documentdb.LogExportProfiler) {
					hasProfiler = true
				}
			}
			if !hasAudit && !hasProfiler {
				results.Add(
					"Neither CloudWatch audit nor profiler log exports are enabled.",
					&cluster,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckProjectLevelOslogin = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0042",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "project-level-oslogin",
		Summary:     "OS Login should be enabled at project level",
		Impact:      "Access via SSH key cannot be revoked automatically when an IAM user is removed.",
		Resolution:  "Enable OS Login at project level",
		Explanation: `OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformProjectLevelOsloginGoodExamples,
			BadExamples:         terraformProjectLevelOsloginBadExamples,
			Links:               terraformProjectLevelOsloginLinks,
			RemediationMarkdown: terraformProjectLevelOsloginRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		if s.Google.Compute.ProjectMetadata.IsManaged() {
			if s.Google.Compute.ProjectMetadata.EnableOSLogin.IsFalse() {
				results.Add(
					"OS Login is disabled at project level.",
					s.Google.Compute.ProjectMetadata.EnableOSLogin,
				)
			} else {
				results.AddPassed(&s.Google.Compute.ProjectMetadata)
			}
		}
		return
	},
)

package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoDefaultServiceAccount = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0044",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-default-service-account",
		Summary:     "Instances should not use the default service account",
		Impact:      "Instance has full access to the project",
		Resolution:  "Remove use of default service account",
		Explanation: `The default service account has full project access. Instances should instead be assigned the minimal access they need.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoDefaultServiceAccountGoodExamples,
			BadExamples:         terraformNoDefaultServiceAccountBadExamples,
			Links:               terraformNoDefaultServiceAccountLinks,
			RemediationMarkdown: terraformNoDefaultServiceAccountRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.ServiceAccount.Email.IsEmpty() || instance.ServiceAccount.Email.EndsWith("-compute@developer.gserviceaccount.com") {
				results.Add(
					"Instance uses the default service account.",
					instance.ServiceAccount.Email,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)

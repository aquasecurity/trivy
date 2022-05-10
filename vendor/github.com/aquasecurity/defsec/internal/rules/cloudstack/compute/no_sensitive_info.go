package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var scanner = squealer.NewStringScanner()

var CheckNoSensitiveInfo = rules.Register(
	scan.Rule{
		AVDID:       "AVD-CLDSTK-0001",
		Provider:    providers.CloudStackProvider,
		Service:     "compute",
		ShortCode:   "no-sensitive-info",
		Summary:     "No sensitive data stored in user_data",
		Impact:      "Sensitive credentials in the user data can be leaked",
		Resolution:  "Don't use sensitive data in the user data section",
		Explanation: `When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoSensitiveInfoGoodExamples,
			BadExamples:         terraformNoSensitiveInfoBadExamples,
			Links:               terraformNoSensitiveInfoLinks,
			RemediationMarkdown: terraformNoSensitiveInfoRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.CloudStack.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if scanner.Scan(instance.UserData.Value()).TransgressionFound {
				results.Add(
					"Instance user data contains secret(s).",
					instance.UserData,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
